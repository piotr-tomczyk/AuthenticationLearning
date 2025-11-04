const express = require('express')
const app = express()
const cors = require('cors');
const port = 3000
const pg = require('pg');
const cookieParser = require("cookie-parser");
const connectionString = "postgres://postgres:admin@localhost:5432/auth";
const DiscordStrategy = require('passport-discord').Strategy;
const passport = require('passport');
const dotenv = require('dotenv').config()
const DatabaseService = require('./services/DatabaseService');
const CookieService = require('./services/CookieService');
const JwtService = require('./services/JwtService');
const SessionService = require('./services/SessionService');
const UserService = require('./services/UserService');
const { isSessionExpired } = require('./utils/SessionUtils');
const { cookieValueExists } = require('./utils/CookieUtils');
const { getPrivateKey } = require('./utils/JwtUtils');
const { areUserParamsValid, USERS_TABLE_NAME } = require('./utils/UserUtils');

const client = new pg.Client(connectionString);
client.connect();
const databaseService = new DatabaseService(client);
const cookieService = new CookieService();
const jwtService = new JwtService(databaseService, cookieService)
const sessionService = new SessionService(databaseService);
const passwordService = new PasswordService();
const userService = new UserService(databaseService, passwordService);
app.use(express.json());
app.use(cookieParser());
app.use(cors({
    origin: 'http://localhost:5173',
    credentials: true,
}));

registerDiscordAuth();

app.get('/api/me', async (req, res) => {
    const {sessionId, refreshJwtToken} = req.cookies;
    if (!cookieService.cookieValuesExist(req.cookies)) {
        res.json({
            loggedIn: false,
        });
        return;
    }
    let userId;
    let user;

    if (cookieValueExists(sessionId)) {
        const session = await databaseService.getSession(sessionId);
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
            = await jwtService.handleJwtTokenRefresh(res, refreshJwtToken, 'api/me');
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
        user = await databaseService.getUserById(userId);
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
        const user = await databaseService.getUserByUsername(username);
        if (user?.username) {
            res.status(400).send({ loggedIn: false });
            return;
        }

        const userId = await userService.createUserWithPassword(username, password);

        if (withJwt) {
            await jwtService.createJwtTokensAndSetCookies({ userId, refreshJwtTokenVersion: '1' }, res);
        } else {
            const session = await sessionService.createSession(userId);
            cookieService.setSessionCookie(res, session);
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
        const user = await databaseService.getNonDiscordUserByUsername(username);
        if (!user) {
            res.status(400).send({ loggedIn: false });
            return;
        }

        const isPasswordValid = await passwordService.validatePassword(password, user.password);
        if (!isPasswordValid) {
            res.status(401).send({ loggedIn: false });
            return;
        }
        if (withJwt) {
            await jwtService.createJwtTokensAndSetCookies(user, res);
        } else {
            const session = await sessionService.createSession(user.userId);
            cookieService.setSessionCookie(res, session);
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
    if (!cookieService.cookieValuesExist(req.cookies)) {
        res.status(401).send();
        return;
    }
    let userId;
    if (cookieValueExists(authJwtToken)) {
        const secret = await getPrivateKey();
        try {
            const payload = jwtService.verifyJwtToken(authJwtToken, secret);
            userId = payload?.userId;
        } catch (error) {
            if (error.message !== 'jwt expired') {
                console.error('api/increment Error verifying authJWT', error);
                res.status(401).send();
            }

            const handleRefreshTokenResponse = await jwtService.handleJwtTokenRefresh(
                res,
                refreshJwtToken,
                'api/increment'
            );

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
        const session = await databaseService.getSession(sessionId);
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

    const count = await databaseService.increaseUserCountProperty(userId);
    res.status(200).send({
        count,
    });
});

app.post('/api/signout', async (req, res) => {
    try {
        const { sessionId, refreshJwtToken } = req.cookies;
        if (!cookieService.cookieValuesExist(req.cookies)) {
            cookieService.clearCookie(res, 'sessionId');
            cookieService.clearCookie(res, 'refreshJwtToken');
            cookieService.clearCookie(res, 'authJwtToken');

            res.status(401).send();
            return;
        }

        if (cookieValueExists(refreshJwtToken)) {
            const secret = await getPrivateKey();
            try {
                const payload = jwtService.verifyJwtToken(refreshJwtToken, secret);
                const { userId } = payload;
                await databaseService.updateRefreshTokenVersionForUser(userId)
            } catch (error) {
                console.error('api/signout Error verifying refreshJWT or updating refresh_token_version', error);
                res.status(401).send();
            }

            cookieService.clearCookie(res, 'refreshJwtToken');
            cookieService.clearCookie(res, 'authJwtToken');
        }
        if (cookieValueExists(sessionId)) {
            const session = await databaseService.getSession(sessionId);
            if (!session) {
                cookieService.clearCookie(res, 'sessionId');
                res.status(401).send();
                return;
            }

            await databaseService.deleteSessionById(sessionId);
            cookieService.clearCookie(res, 'sessionId');
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
        const session = await sessionService.createSession(user.id);
        cookieService.setSessionCookie(res, session);

        res.redirect('http://localhost:5173');
    })(req, res, next);
});

app.listen(port, () => {
  console.log(`Example app listening on port ${port}`)
})

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
                const userResponse = await databaseService.queryDatabase(`SELECT * FROM ${USERS_TABLE_NAME} WHERE userid = $1`, [profile.id]);
                if (areUserParamsValid(userResponse)) {
                    return cb(profile);
                }

                await databaseService.queryDatabase(
                    `INSERT INTO ${USERS_TABLE_NAME} (userid, username, password, login_type) VALUES ($1, $2, $3, $4)`,
                    [profile.id, profile.username, '', 'discord']
                );

                return cb(profile);
            } catch(error) {
                console.log('Error authenticating with discord', error);
            }
    }));
}
