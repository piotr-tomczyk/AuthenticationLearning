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
    const {sessionId} = req.cookies;
    if (!sessionId) {
        res.json({
            loggedIn: false,
        });
        return;
    }
    const responseSession = await client.query('SELECT * FROM auth.public.sessions WHERE sessionid = $1', [sessionId]);
    if (!responseSession.rows.length) {
        res.json({
            loggedIn: false,
        });
        return;
    }
    if (responseSession?.rows?.[0]?.expiresat?.getTime() < Date.now()) {
        res.json({
            loggedIn: false,
        })
        return;
    }
    const responseUser = await client.query('SELECT * FROM auth.public.users WHERE userid = $1', [responseSession.rows[0].userid]);
    const user = responseUser.rows[0];
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
            const jwtToken = await createJwt(userId);
            res.cookie('jwtToken', jwtToken, {
                expires: new Date(Date.now() + 1000 * 3600 * 24 * 30),
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
            const jwtToken = await createJwt(user.userid);
            res.cookie('jwtToken', jwtToken, {
                expires: new Date(Date.now() + 1000 * 3600 * 24 * 30),
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
    const { sessionId, jwtToken } = req.cookies;
    if (!sessionId && jwtToken === 'j:null') {
        res.status(401).send();
        return;
    }
    let userId;
    if (jwtToken && jwtToken !== 'j:null') {
        try {
            const secret = await fs.readFile('./private_key.pem', { encoding: 'utf8', expiresIn: "5m" });
            const payload = jwt.verify(jwtToken, secret);
            userId = payload.userId;
        } catch (error) {
            console.error('api/increment Error verifying JWT', error);
            res.status(401).send();
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
        const { sessionId, jwtToken } = req.cookies;
        if (!sessionId && !jwtToken) {
            res.cookie('sessionId', null, {
                expires: 1,
                secure: false,
                httpOnly: true,
                sameSite: 'strict',
            });
            res.cookie('jwtToken', null, {
                expires: 1,
                secure: false,
                httpOnly: true,
                sameSite: 'strict',
            });
            res.status(401).send();
            return;
        }

        if (jwtToken && jwtToken !== 'j:null') {
            res.cookie('jwtToken', null, {
                expires: 0,
                secure: false,
                httpOnly: true,
                sameSite: 'strict',
            });
        } else {
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
    const secret = await fs.readFile('./private_key.pem', { encoding: 'utf8', expiresIn: "5m" });
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

                return cb(JSON.stringify(profile));
            } catch(error) {
                console.log('Error authenticating with discord', error);
            }

    }));
}
