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
        const sessionResponse = await queryDatabase(`SELECT * FROM ${SESSIONS_TABLE_NAME} WHERE sessionid = $1`, [sessionId]);
        if (!areSessionParamsValid(sessionResponse)) {
            res.json({
                loggedIn: false,
            });
            return;
        }
        const session = mapDatabaseSession(sessionResponse);

        userId = session.userId;

        if (session.expiresAt?.getTime() < Date.now()) {
            res.json({
                loggedIn: false,
            })
            return;
        }
    } else if (cookieValueExists(refreshJwtToken)) {
        const secret = await fs.readFile('./private_key.pem', { encoding: 'utf8', expiresIn: "5m" });
        try {
            const payload = jwt.verify(refreshJwtToken, secret);
            userId = payload.userId;
            const userResponse = await queryDatabase(
                `SELECT * FROM ${USERS_TABLE_NAME} WHERE userid = $1`,
                [userId]
            );
            if (!areUserParamsValid(userResponse)) {
                res.status(404).send();
                return;
            }

            user = mapDatabaseUser(userResponse);

            if (user.refreshJwtVersion !== payload?.version) {
                console.error('Refresh JWT version doesnt match');
                res.status(401).send();
                return;
            } else {
                const authJwtToken = await createJwt(userId);
                res.cookie('authJwtToken', authJwtToken, {
                    expires: new Date(Date.now() + 1000 * 60 * 2),
                    secure: false,
                    httpOnly: true,
                    sameSite: 'strict',
                });
            }
        } catch (error) {
            console.error('api/me Error verifying refreshJWT', error);
            res.status(401).send();
            return;
        }
    } else {
        res.json({
            loggedIn: false,
        })
        return;
    }

    if (!user) {
        const userResponse = await queryDatabase(`SELECT * FROM ${USERS_TABLE_NAME} WHERE userid = $1`, [userId]);
        if (!areUserParamsValid(userResponse)) {
            res.status(404).send();
            return;
        }

        user = mapDatabaseUser(userResponse);
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
        const user = await queryDatabase(`SELECT username FROM ${USERS_TABLE_NAME} WHERE username = $1`, [username]);
        if (user?.username) {
            res.status(400).send({ loggedIn: false });
            return;
        }

        const hashedPassword = await generatePassword(password);
        const userId = crypto.randomUUID();
        await queryDatabase(`INSERT INTO ${USERS_TABLE_NAME} (userid, username, password) VALUES ($1, $2, $3)`, [userId, username, hashedPassword]);
        if (withJwt) {
            const authJwtToken = await createJwt(userId);
            const refreshJwtToken = await createRefreshJwt(userId, "1");
            res.cookie('authJwtToken', authJwtToken, {
                expires: new Date(Date.now() + 1000 * 60 * 2),
                secure: false,
                httpOnly: true,
                sameSite: 'strict',
            });

            res.cookie('refreshJwtToken', refreshJwtToken, {
                expires: new Date(Date.now() + 1000 * 60 * 60 * 24 * 30),
                secure: false,
                httpOnly: true,
                sameSite: 'strict',
            });
        } else {
            const session = await createSession(userId);
            res.cookie('sessionId', session, {
                expires: new Date(Date.now() + 1000 * 3600 * 24 * 30),
                secure: false,
                httpOnly: true,
                sameSite: 'strict',
            });
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
        const userResponse = await queryDatabase(`SELECT * FROM ${USERS_TABLE_NAME} WHERE username = $1 AND login_type != $2`, [username, 'discord']);
        if (!areUserParamsValid(userResponse)) {
            res.status(400).send({ loggedIn: false });
            return;
        }

        const user = mapDatabaseUser(userResponse);

        const isPasswordValid = await validatePassword(password, user.password);
        if (!isPasswordValid) {
            res.status(401).send({ loggedIn: false });
            return;
        }
        if (withJwt) {
            const userId = user.userId;
            const refreshTokenVersion = user.refreshJwtVersion;
            const authJwtToken = await createJwt(userId);
            const refreshJwtToken = await createRefreshJwt(userId, refreshTokenVersion);
            res.cookie('authJwtToken', authJwtToken, {
                expires: new Date(Date.now() + 1000 * 60 * 2),
                secure: false,
                httpOnly: true,
                sameSite: 'strict',
            });

            res.cookie('refreshJwtToken', refreshJwtToken, {
                expires: new Date(Date.now() + 1000 * 60 * 60 * 24 * 30),
                secure: false,
                httpOnly: true,
                sameSite: 'strict',
            });
        } else {
            const session = await createSession(user.userId);
            res.cookie('sessionId', session, {
                expires: new Date(Date.now() + 1000 * 3600 * 24 * 30),
                secure: false,
                httpOnly: true,
                sameSite: 'strict',
            });
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
    if (!cookieValueExists(sessionId) && !cookieValueExists(authJwtToken) && !cookieValueExists(refreshJwtToken)) {
        res.status(401).send();
        return;
    }
    let userId;
    let user;
    if (cookieValueExists(authJwtToken)) {
        const secret = await fs.readFile('./private_key.pem', { encoding: 'utf8', expiresIn: "5m" });
        try {
            const payload = jwt.verify(authJwtToken, secret);
            userId = payload.userId;
        } catch (error) {
            if (error.message !== 'jwt expired') {
                console.error('api/increment Error verifying authJWT', error);
                res.status(401).send();
            }
            try {
                const payload = jwt.verify(refreshJwtToken, secret);
                userId = payload.userId;
                const userResponse = await queryDatabase(`SELECT * FROM ${USERS_TABLE_NAME} WHERE userid = $1`, [userId]);
                if (!areUserParamsValid(userResponse)) {
                    res.status(404).send();
                    return;
                }

                user = mapDatabaseUser(userResponse);
                if (user.refreshJwtVersion !== payload.version) {
                    console.error('Refresh JWT version doesnt match');
                    res.status(401).send();
                    return;
                } else {
                    const authJwtToken = await createJwt(userId);
                    res.cookie('authJwtToken', authJwtToken, {
                        expires: new Date(Date.now() + 1000 * 60 * 2),
                        secure: false,
                        httpOnly: true,
                        sameSite: 'strict',
                    });
                }
            } catch (error) {
                console.error('api/increment Error verifying refreshJWT', error);
                res.status(401).send();
                return;
            }
        }
    } else {
        const sessionResponse = await queryDatabase(`SELECT * FROM ${SESSIONS_TABLE_NAME} WHERE sessionid = $1`, [sessionId]);
        if (!areSessionParamsValid(sessionResponse)) {
            res.status(401).send();
            return;
        }

        const session = mapDatabaseSession(sessionResponse);
        if (session.expiresAt.getTime() < Date.now()) {
            res.status(401).send();
            return;
        }
        userId = session.userId;
    }
    const count = await queryDatabase(`UPDATE ${USERS_TABLE_NAME} SET count = count + 1 WHERE userid=$1 RETURNING count`, [userId]);
    res.status(200).send({
        count,
    });
});

app.post('/api/signout', async (req, res) => {
    try {
        const { sessionId, refreshJwtToken } = req.cookies;
        if (!cookieValuesExist(req.cookies)) {
            res.cookie('sessionId', null, {
                expires: 1,
                secure: false,
                httpOnly: true,
                sameSite: 'strict',
            });
            res.cookie('authJwtToken', null, {
                expires: 1,
                secure: false,
                httpOnly: true,
                sameSite: 'strict',
            });
            res.cookie('refreshJwtToken', null, {
                expires: 1,
                secure: false,
                httpOnly: true,
                sameSite: 'strict',
            });

            res.status(401).send();
            return;
        }

        if (cookieValueExists(refreshJwtToken)) {
            const secret = await fs.readFile('./private_key.pem', { encoding: 'utf8' });
            try {
                const payload = jwt.verify(refreshJwtToken, secret);
                const { userId } = payload;
                const newVersion = crypto.randomUUID();
                await queryDatabase(
                    `UPDATE ${USERS_TABLE_NAME} SET refresh_jwt_version = $1 WHERE userid = $2;`,
                    [newVersion, userId]
                );
            } catch (error) {
                console.error('api/signout Error verifying refreshJWT or updating refresh_token_version', error);
                res.status(401).send();
            }

            res.cookie('refreshJwtToken', null, {
                expires: 0,
                secure: false,
                httpOnly: true,
                sameSite: 'strict',
            });
            res.cookie('authJwtToken', null, {
                expires: 0,
                secure: false,
                httpOnly: true,
                sameSite: 'strict',
            });
        }
        if (cookieValueExists(sessionId)) {
            const sessionResponse = await queryDatabase(`SELECT * FROM ${SESSIONS_TABLE_NAME} WHERE sessionid = $1`, [sessionId]);
            if (!areSessionParamsValid(sessionResponse)) {
                res.cookie('sessionId', null, {
                    expires: 0,
                    secure: false,
                    httpOnly: true,
                    sameSite: 'strict',
                });
                res.status(401).send();
                return;
            }

            await queryDatabase(`DELETE FROM ${SESSIONS_TABLE_NAME} WHERE sessionid=$1`, [sessionId]);

            res.cookie('sessionId', null, {
                expires: 0,
                secure: false,
                httpOnly: true,
                sameSite: 'strict',
            });
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
        res.cookie('sessionId', session, {
            expires: new Date(Date.now() + 1000 * 3600 * 24 * 30),
            secure: false,
            httpOnly: true,
            sameSite: 'strict',
        });
        // Successful authentication
        res.redirect('http://localhost:5173');
    })(req, res, next);
});

app.listen(port, () => {
  console.log(`Example app listening on port ${port}`)
})

async function createSession(userId) {
    await queryDatabase(`DELETE FROM ${SESSIONS_TABLE_NAME} WHERE expiresat<to_timestamp($1)`, [Math.floor(Date.now() / 1000)]);
    const sessionId = crypto.randomUUID();
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
