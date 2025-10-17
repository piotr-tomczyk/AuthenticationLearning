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

const client = new pg.Client(connectionString);
client.connect();
app.use(express.json());
app.use(cookieParser());
app.use(cors({
    origin: 'http://localhost:5173',
    credentials: true,
}));

registerDiscordAuth();

app.get('/api', async (req, res) => {
    const response = await client.query('SELECT * FROM auth.public.users');
    res.json({ data: response.rows });
})

app.get('/api/me', async (req, res) => {
    const {sessionId, authJwtToken, refreshJwtToken} = req.cookies;
    if ((!sessionId || sessionId === 'j:null') &&
        (!authJwtToken || authJwtToken === 'j:null') &&
        (!refreshJwtToken || refreshJwtToken === 'j:null')
    ) {
        res.json({
            loggedIn: false,
        });
        return;
    }
    let userId;
    let user;
    if (sessionId && sessionId !== 'j:null') {
        const responseSession = await client.query('SELECT * FROM auth.public.sessions WHERE sessionid = $1', [sessionId]);
        const session = responseSession?.rows?.[0];
        userId = session.userid;
        if (!responseSession.rows.length) {
            res.json({
                loggedIn: false,
            });
            return;
        }
        if (session.expiresat?.getTime() < Date.now()) {
            res.json({
                loggedIn: false,
            })
            return;
        }
    } else if (refreshJwtToken && refreshJwtToken !== 'j:null') {
        const secret = await fs.readFile('./private_key.pem', { encoding: 'utf8', expiresIn: "5m" });
        try {
            const payload = jwt.verify(refreshJwtToken, secret);
            userId = payload.userId;
            const responseUser = await client.query('SELECT * FROM auth.public.users WHERE userid = $1', [userId]);
            user = responseUser.rows[0];
            if (user.refresh_jwt_version !== payload.version) {
                console.error('Refresh JWT version doesnt match');
                res.status(401).send();
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
        }
    } else {
        res.json({
            loggedIn: false,
        })
        return;
    }

    if (!user) {
        const responseUser = await client.query('SELECT * FROM auth.public.users WHERE userid = $1', [userId]);
        user = responseUser.rows[0];
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
        const response = await client.query('SELECT username FROM auth.public.users WHERE username = $1', [username]);
        if (response?.rows?.length > 0) {
            res.status(400).send({ loggedIn: false });
            return;
        }
        const hashedPassword = await generatePassword(password);
        const userId = crypto.randomUUID();
        await client.query('INSERT INTO auth.public.users (userid, username, password) VALUES ($1, $2, $3)', [userId, username, hashedPassword]);
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
        const response = await client.query('SELECT * FROM auth.public.users WHERE username = $1 AND login_type != $2', [username, 'discord']);
        if (!response?.rows?.length) {
            res.status(400).send({ loggedIn: false });
            return;
        }
        const user = response.rows[0];
        const isPasswordValid = await validPassword(password, user.password);
        if (!isPasswordValid) {
            res.status(401).send({ loggedIn: false });
            return;
        }
        if (withJwt) {
            const userId = user.userid;
            const refreshTokenVersion = user.refresh_jwt_version;
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
            const session = await createSession(user.userid);
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
    if ((!sessionId || sessionId === 'j:null')
        && (!authJwtToken || authJwtToken === 'j:null')
        && (!refreshJwtToken || refreshJwtToken === 'j:null')
    ) {
        res.status(401).send();
        return;
    }
    let userId;
    let user;
    if (authJwtToken && authJwtToken !== 'j:null') {
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
                const responseUser = await client.query('SELECT * FROM auth.public.users WHERE userid = $1', [userId]);
                user = responseUser.rows[0];
                if (user.refresh_jwt_version !== payload.version) {
                    console.error('Refresh JWT version doesnt match');
                    res.status(401).send();
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
            }
        }
    } else {
        const responseSession = await client.query('SELECT * FROM auth.public.sessions WHERE sessionid = $1', [sessionId]);
        if (!responseSession.rows.length) {
            res.status(401).send();
            return;
        }
        const session = responseSession?.rows?.[0];
        if (session?.expiresat.getTime() < Date.now()) {
            res.status(401).send();
            return;
        }
        userId = session.userid;
    }
    const countResponse = await client.query('UPDATE auth.public.users SET count = count + 1 WHERE userid=$1 RETURNING count', [userId]);
    res.status(200).send({
        count: countResponse.rows[0].count,
    });
});

app.post('/api/signout', async (req, res) => {
    try {
        const { sessionId, authJwtToken, refreshJwtToken } = req.cookies;
        if ((!sessionId || sessionId === 'j:null')
        && (!authJwtToken || authJwtToken === 'j:null')
        && (!refreshJwtToken || refreshJwtToken === 'j:null')) {
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

        if (refreshJwtToken && refreshJwtToken !== 'j:null') {
            const secret = await fs.readFile('./private_key.pem', { encoding: 'utf8' });
            try {
                const payload = jwt.verify(refreshJwtToken, secret);
                const { userId } = payload;
                const newVersion = crypto.randomUUID();
                await client.query(
                    'UPDATE auth.public.users SET refresh_jwt_version = $1 WHERE userid = $2;',
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
        if (sessionId && sessionId !== 'j:null') {
            const responseSession = await client.query('SELECT * FROM auth.public.sessions WHERE sessionid = $1', [sessionId]);
            if (!responseSession.rows.length) {
                res.cookie('sessionId', null, {
                    expires: 0,
                    secure: false,
                    httpOnly: true,
                    sameSite: 'strict',
                });
                res.status(401).send();
                return;
            }
            await client.query('DELETE FROM auth.public.sessions WHERE sessionid=$1', [sessionId]);
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
    await client.query('DELETE FROM auth.public.sessions WHERE expiresat<to_timestamp($1)', [Math.floor(Date.now() / 1000)]);
    const sessionId = crypto.randomUUID();
    await client.query('INSERT INTO auth.public.sessions (sessionid, userid, expiresat) VALUES ($1, $2, to_timestamp($3))', [sessionId, userId, Math.floor((Date.now() + 1000 * 3600 * 24 * 30) / 1000)]);
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
function validPassword(password, hash) {
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
                const userResponse = await client.query('SELECT * FROM auth.public.users WHERE userid = $1', [profile.id]);
                if (userResponse?.rows?.length > 0) {
                    return cb(profile);
                }
                await client.query(
                    'INSERT INTO auth.public.users (userid, username, password, login_type) VALUES ($1, $2, $3, $4)',
                    [profile.id, profile.username, '', 'discord']
                );

                return cb(profile);
            } catch(error) {
                console.log('Error authenticating with discord', error);
            }

    }));
}
