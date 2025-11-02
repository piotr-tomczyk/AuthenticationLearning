const express = require('express')
const app = express()
const cors = require('cors');
const port = 3000
const pg = require('pg');
const bcrypt = require('bcrypt');
const cookieParser = require("cookie-parser");
const crypto = require('node:crypto');
const fs = require('node:fs/promises');
const connectionString = "postgres://postgres:admin@localhost:5432/auth";
const jwt = require('jsonwebtoken');
const DiscordStrategy = require('passport-discord').Strategy;
const passport = require('passport');
const dotenv = require('dotenv').config()

const SESSIONS_TABLE_NAME = 'auth.public.sessions';
const USERS_TABLE_NAME = 'auth.public.users';

const client = new pg.Client(connectionString);
client.connect();

app.use(express.json());
app.use(cookieParser());
app.use(cors({
    origin: 'http://localhost:5173',
    credentials: true,
}));

registerDiscordAuth();

app.get('/api/me', async (req, res) => {
    const {sessionId, refreshJwtToken} = req.cookies;
    if (!cookieValuesExist(req.cookies)) {
        res.json({
            loggedIn: false,
        });
        return;
    }
    let userId;
    let user;

    if (cookieValueExists(sessionId)) {
        const session = await getSessionFromDb(sessionId);
        if (!session) {
            res.json({
                loggedIn: false,
            });
            return;
        }

        if (isSessionExpired(session)) {
            res.json({
                loggedIn: false,
            })
            return;
        }

        userId = session.userId;
    } else if (cookieValueExists(refreshJwtToken)) {
        const handleRefreshTokenResponse
            = await handleJwtTokenRefresh(res, refreshJwtToken, 'api/me');
        if (handleRefreshTokenResponse.error) {
            if (handleRefreshTokenResponse.error.message === 'no_valid_params') {
                res.status(404).send();
                return;
            } else {
                res.status(401).send();
                return;
            }
        }
        user = handleRefreshTokenResponse.user;
        userId = handleRefreshTokenResponse.userId;
    } else {
        res.json({
            loggedIn: false,
        })
        return;
    }

    if (!user) {
        user = await getUserFromDbById(userId);
        if (!user) {
            res.status(404).send();
            return;
        }
    }

    res.json({
        loggedIn: true,
        username: user.username,
        count: user.count,
    });
});

app.post('/api/register', async (req, res) => {
    const { username, password, withJwt, } = req.body;
    try {
        const user = await getUserFromDbByUsername(username);
        if (user?.username) {
            res.status(400).send({ loggedIn: false });
            return;
        }

        const userId = await createUserWithPasswordInDb(username, password);

        if (withJwt) {
            await createJwtTokensInDbAndSetCookies({ userId, refreshJwtTokenVersion: '1' }, res);
        } else {
            const session = await createSession(userId);
            setSessionCookie(res, session);
        }

        res.setHeader('Content-Type', 'application/json');
        res.status(201).json({ loggedIn: true, username, count: 0 });
    } catch(error) {
        console.error('api/register Registration error', error);
        res.status(500).json({ loggedIn: false });
    }
});

app.post('/api/login', async (req, res) => {
    const { username, password, withJwt, } = req.body;
    try {
        const user = await getNonDiscordUserFromDbByUsername(username);
        if (!user) {
            res.status(400).send({ loggedIn: false });
            return;
        }

        const isPasswordValid = await validatePassword(password, user.password);
        if (!isPasswordValid) {
            res.status(401).send({ loggedIn: false });
            return;
        }
        if (withJwt) {
            await createJwtTokensInDbAndSetCookies(user, res);
        } else {
            const session = await createSession(user.userId);
            setSessionCookie(res, session);
        }
        res.setHeader('Content-Type', 'application/json');
        res.status(200).json({ loggedIn: true, username: user.username, count: user.count });
    } catch(error) {
        console.error('api/login Login error', error);
        res.status(500).json({ loggedIn: false });
    }
});

app.patch('/api/increment', async (req, res) => {
    const { sessionId, authJwtToken, refreshJwtToken } = req.cookies;
    if (!cookieValuesExist(req.cookies)) {
        res.status(401).send();
        return;
    }
    let userId;
    if (cookieValueExists(authJwtToken)) {
        const secret = await getPrivateKey();
        try {
            const payload = verifyJwtToken(authJwtToken, secret);
            userId = payload?.userId;
        } catch (error) {
            if (error.message !== 'jwt expired') {
                console.error('api/increment Error verifying authJWT', error);
                res.status(401).send();
            }

            const handleRefreshTokenResponse = await handleJwtTokenRefresh(res, refreshJwtToken, 'api/increment');
            if (handleRefreshTokenResponse.error) {
                if (handleRefreshTokenResponse.error.message === 'no_valid_params') {
                    res.status(404).send();
                    return;
                } else {
                    res.status(401).send();
                    return;
                }
            }

            userId = handleRefreshTokenResponse.userId;
        }
    } else {
        const session = await getSessionFromDb(sessionId);
        if (!session) {
            res.status(401).send();
            return;
        }

        if (isSessionExpired(session)) {
            res.status(401).send();
            return;
        }

        userId = session.userId;
    }

    const count = await increaseUserCountPropertyInDb(userId);
    res.status(200).send({
        count,
    });
});

app.post('/api/signout', async (req, res) => {
    try {
        const { sessionId, refreshJwtToken } = req.cookies;
        if (!cookieValuesExist(req.cookies)) {
            clearCookie(res, 'sessionId');
            clearCookie(res, 'refreshJwtToken');
            clearCookie(res, 'authJwtToken');

            res.status(401).send();
            return;
        }

        if (cookieValueExists(refreshJwtToken)) {
            const secret = await getPrivateKey();
            try {
                const payload = verifyJwtToken(refreshJwtToken, secret);
                const { userId } = payload;
                await updateRefreshTokenVersionInDbForUser(userId)
            } catch (error) {
                console.error('api/signout Error verifying refreshJWT or updating refresh_token_version', error);
                res.status(401).send();
            }

            clearCookie(res, 'refreshJwtToken');
            clearCookie(res, 'authJwtToken');
        }
        if (cookieValueExists(sessionId)) {
            const session = await getSessionFromDb(sessionId);
            if (!session) {
                clearCookie(res, 'sessionId');
                res.status(401).send();
                return;
            }

            await deleteSessionFromDbById(sessionId);
            clearCookie(res, 'sessionId');
        }
        res.status(200).send();
    } catch(error) {
        console.error('api/signout Error', error);
        res.status(500).send();
    }

});

app.get('/api/login/discord', passport.authenticate('discord'), async (req, res) => {
    res.status(200).send();
});

app.get('/api/discord/callback', (req, res, next) => {
    passport.authenticate('discord', { failureRedirect: '/' }, async (user) => {
        const session = await createSession(user.id);
        setSessionCookie(res, session);

        res.redirect('http://localhost:5173');
    })(req, res, next);
});

app.listen(port, () => {
  console.log(`Example app listening on port ${port}`)
})

async function createSession(userId) {
    await deleteExpiredSessionFromDb();
    const sessionId = crypto.randomUUID();
    await insertSessionIntoDb({ sessionId, userId , expiresAt: (Date.now() + 1000 * 3600 * 24 * 30) / 1000 })
    await queryDatabase(`INSERT INTO ${SESSIONS_TABLE_NAME} (sessionid, userid, expiresat) VALUES ($1, $2, to_timestamp($3))`, [sessionId, userId, Math.floor((Date.now() + 1000 * 3600 * 24 * 30) / 1000)]);
    return sessionId;
}

async function createJwt(userId) {
    const payload = {
        userId,
    };
    const secret = await fs.readFile('./private_key.pem', { encoding: 'utf8' });
    const jwtToken = jwt.sign(payload, secret, { algorithm: 'RS256', expiresIn: '1m' });
    return jwtToken;
}

async function createRefreshJwt(userId, version = "1") {
    const payload = {
        userId,
        version,
    };
    const secret = await fs.readFile('./private_key.pem', { encoding: 'utf8', expiresIn: "30d" });
    const jwtToken = jwt.sign(payload, secret, { algorithm: 'RS256' });
    return jwtToken;
}

async function generatePassword(password) {
    const saltRounds = 10;
    return bcrypt.hash(password, saltRounds);
}

function validatePassword(password, hash) {
    return bcrypt.compare(password, hash);
}

function registerDiscordAuth() {
    const authScopes = ['identify', 'email'];
    passport.use(new DiscordStrategy({
            clientID: process.env.DISCORD_CLIENT_ID,
            clientSecret: process.env.DISCORD_CLIENT_SECRET,
            callbackURL: 'http://localhost:3000/api/discord/callback',
            scope: authScopes
        },
        async function(accessToken, refreshToken, profile, cb) {
            try {
                const userResponse = await queryDatabase(`SELECT * FROM ${USERS_TABLE_NAME} WHERE userid = $1`, [profile.id]);
                if (areUserParamsValid(userResponse)) {
                    return cb(profile);
                }

                await queryDatabase(
                    `INSERT INTO ${USERS_TABLE_NAME} (userid, username, password, login_type) VALUES ($1, $2, $3, $4)`,
                    [profile.id, profile.username, '', 'discord']
                );

                return cb(profile);
            } catch(error) {
                console.log('Error authenticating with discord', error);
            }

    }));
}

function cookieValuesExist(cookies) {
    const { sessionId, authJwtToken, refreshJwtToken } = cookies;
    return cookieValueExists(sessionId) || cookieValueExists(authJwtToken) || cookieValueExists(refreshJwtToken);
}

function cookieValueExists(cookieValue) {
    return cookieValue && cookieValue !== 'j:null';
}

async function queryDatabase(query, variables) {
    const response = await client.query(query, variables);
    return response?.rows?.[0];
}

function mapDatabaseSession(session) {
    return {
        sessionId: session.sessionid,
        userId: session.userid,
        expiresAt: session.expiresat,
    }
}

function mapDatabaseUser(user) {
    return {
        userId: user.userid,
        username: user.username,
        password: user.password,
        count: user.count,
        loginType: user.login_type,
        refreshJwtVersion: user.refresh_jwt_version,
    }
}

function areSessionParamsValid(session) {
    return session && session.userid && session.expiresat;
}

function areUserParamsValid(user) {
    return user && user.username && user.password && user.count && user.login_type && user.refresh_jwt_version;
}

function clearCookie(res, cookieName) {
    res.cookie(cookieName, null, {
        expires: 0,
        secure: false,
        httpOnly: true,
        sameSite: 'strict',
    });
}

async function handleJwtTokenRefresh(res, refreshJwtToken, errorPrefix) {
    const secret = await fs.readFile('./private_key.pem', { encoding: 'utf8', expiresIn: "5m" });
    const returnData = {
        userId: null,
        user: null,
        error: null,
    }
    try {
        const payload = jwt.verify(refreshJwtToken, secret);
        returnData.userId = payload.userId;
        const userResponse = await queryDatabase(
            `SELECT * FROM ${USERS_TABLE_NAME} WHERE userid = $1`,
            [userId]
        );
        if (!areUserParamsValid(userResponse)) {
            returnData.error = {
                message: 'no_valid_params',
            };
            return returnData;
        }

        returnData.user = mapDatabaseUser(userResponse);

        if (returnData.user.refreshJwtVersion !== payload?.version) {
            console.error(`[${errorPrefix}] Refresh JWT version doesnt match`);
            // res.status(401).send();
            returnData.error = {
                message: 'no_version_match',
            };
            return returnData;
        } else {
            const authJwtToken = await createJwt(returnData.userId);
            setAuthJwtCookie(res, authJwtToken);
        }
        return returnData;
    } catch (error) {
        console.error(`[${errorPrefix}] Error verifying refreshJWT`, error);
        returnData.error = {
            message: 'unknown_error',
        };
        return returnData;
    }
}

function setSessionCookie(res, sessionId) {
    res.cookie('sessionId', sessionId, {
        expires: new Date(Date.now() + 1000 * 3600 * 24 * 30),
        secure: false,
        httpOnly: true,
        sameSite: 'strict',
    });
}

function setRefreshJwtCookie(res, jwtToken) {
    res.cookie('refreshJwtToken', jwtToken, {
        expires: new Date(Date.now() + 1000 * 60 * 60 * 24 * 30),
        secure: false,
        httpOnly: true,
        sameSite: 'strict',
    });
}

function setAuthJwtCookie(res, jwtToken) {
    res.cookie('authJwtToken', jwtToken, {
        expires: new Date(Date.now() + 1000 * 60 * 2),
        secure: false,
        httpOnly: true,
        sameSite: 'strict',
    });
}

async function getSessionFromDb(sessionId) {
    const sessionResponse = await queryDatabase(`SELECT * FROM ${SESSIONS_TABLE_NAME} WHERE sessionid = $1`, [sessionId]);
    if (!areSessionParamsValid(sessionResponse)) {
        return null;
    }
    const session = mapDatabaseSession(sessionResponse);
    return session;
}

function isSessionExpired(session) {
    return session.expiresAt?.getTime() < Date.now();
}

async function deleteSessionFromDbById(sessionId) {
    return queryDatabase(`DELETE FROM ${SESSIONS_TABLE_NAME} WHERE sessionid=$1`, [sessionId]);
}

async function deleteExpiredSessionFromDb() {
    return queryDatabase(
        `DELETE FROM ${SESSIONS_TABLE_NAME} WHERE expiresat<to_timestamp($1)`,
        [Math.floor(Date.now() / 1000)]
    );
}

async function insertSessionIntoDb(params) {
    const { sessionId, userId, expiresAt, } = params;
    return queryDatabase(
        `INSERT INTO ${SESSIONS_TABLE_NAME} (sessionid, userid, expiresat) VALUES ($1, $2, to_timestamp($3))`,
        [sessionId, userId, Math.floor(expiresAt)],
    );
}

async function getUserFromDbById(userId) {
    const userResponse = await queryDatabase(
        `SELECT * FROM ${USERS_TABLE_NAME} WHERE userid = $1`,
        [userId]
    );
    if (!areUserParamsValid(userResponse)) {
        return null;
    }

    return mapDatabaseUser(userResponse);
}

async function getUserFromDbByUsername(username) {
    const userResponse = await queryDatabase(
        `SELECT * FROM ${USERS_TABLE_NAME} WHERE userid = $1`,
        [username]
    );
    if (!areUserParamsValid(userResponse)) {
        return null;
    }

    return mapDatabaseUser(userResponse);
}

async function getNonDiscordUserFromDbByUsername(username) {
    const userResponse = await queryDatabase(
        `SELECT * FROM ${USERS_TABLE_NAME} WHERE username = $1 AND login_type != $2`,
        [username, 'discord']
    );

    if (!areUserParamsValid(userResponse)) {
        return null;
    }

    return mapDatabaseUser(userResponse);
}

async function insertUserIntoDb(params) {
    const { userId, username, hashedPassword } = params;
    return queryDatabase(
        `INSERT INTO ${USERS_TABLE_NAME} (userid, username, password) VALUES ($1, $2, $3)`,
        [userId, username, hashedPassword]
    );
}

async function createUserWithPasswordInDb(username, password) {
    const hashedPassword = await generatePassword(password);
    const userId = crypto.randomUUID();
    await insertUserIntoDb({ userId, username, hashedPassword });
    return userId;
}

async function createJwtTokensInDbAndSetCookies(params, res) {
    const { userId, refreshTokenVersion } = params;
    const authJwtToken = await createJwt(userId);
    const refreshJwtToken = await createRefreshJwt(userId, refreshTokenVersion);

    setAuthJwtCookie(res, authJwtToken)
    setRefreshJwtCookie(res, refreshJwtToken);
}

async function getPrivateKey() {
    return fs.readFile('./private_key.pem', { encoding: 'utf8' });
}

async function increaseUserCountPropertyInDb(userId) {
    return queryDatabase(
        `UPDATE ${USERS_TABLE_NAME} SET count = count + 1 WHERE userid=$1 RETURNING count`,
        [userId]
    );
}

function verifyJwtToken(jwtToken, secret) {
    return jwt.verify(jwtToken, secret);
}

async function updateRefreshTokenVersionInDbForUser(userId) {
    const newRefreshTokenVersion = crypto.randomUUID();
    return queryDatabase(
        `UPDATE ${USERS_TABLE_NAME} SET refresh_jwt_version = $1 WHERE userid = $2;`,
        [newRefreshTokenVersion, userId]
    );
}
