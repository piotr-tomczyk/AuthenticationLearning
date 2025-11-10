const express = require('express');
const { cookieValueExists } = require('../utils/CookieUtils.js');
const { getPrivateKey } = require('../utils/JwtUtils.js');
const { 
    API_ROUTES, 
    HTTP_STATUS, 
    HTTP_HEADERS, 
    RESPONSE, 
    LOG_PREFIX, 
    COOKIE_NAMES,
    JWT,
} = require('../utils/constants.js');

const createAuthRoutes = (app, services, authenticateUser) => {
    const router = express.Router();
    const { 
        databaseService, 
        jwtService, 
        cookieService, 
        passwordService,
        sessionService, 
        userService,
    } = services;

    router.get(API_ROUTES.ME, authenticateUser ,async (req, res) => {
        const { user } = req.context;

        res.json({
            loggedIn: RESPONSE.LOGGED_IN,
            username: user.username,
            count: user.count,
        });
    });

    router.post(API_ROUTES.REGISTER, async (req, res) => {
        const { username, password, withJwt, } = req.body;
        try {
            const user = await databaseService.getUserByUsername(username);
            if (user?.username) {
                res.status(HTTP_STATUS.BAD_REQUEST).send({ loggedIn: RESPONSE.LOGGED_OUT });
                return;
            }

            const userId = await userService.createUserWithPassword(username, password);

            if (withJwt) {
                await jwtService.createJwtTokensAndSetCookies({ userId, refreshJwtTokenVersion: JWT.DEFAULT_REFRESH_VERSION }, res);
            } else {
                const session = await sessionService.createSession(userId);
                cookieService.setSessionCookie(res, session);
            }

            res.setHeader(HTTP_HEADERS.CONTENT_TYPE, HTTP_HEADERS.APPLICATION_JSON);
            res.status(HTTP_STATUS.CREATED).json({ loggedIn: RESPONSE.LOGGED_IN, username, count: RESPONSE.INITIAL_COUNT });
        } catch(error) {
            console.error(`${LOG_PREFIX.REGISTER} Registration error`, error);
            res.status(HTTP_STATUS.INTERNAL_SERVER_ERROR).json({ loggedIn: RESPONSE.LOGGED_OUT });
        }
    });

    router.post(API_ROUTES.LOGIN, async (req, res) => {
        const { username, password, withJwt, } = req.body;
        try {
            const user = await databaseService.getNonDiscordUserByUsername(username);
            if (!user) {
                res.status(HTTP_STATUS.BAD_REQUEST).send({ loggedIn: RESPONSE.LOGGED_OUT });
                return;
            }

            const isPasswordValid = await passwordService.validatePassword(password, user.password);
            if (!isPasswordValid) {
                res.status(HTTP_STATUS.UNAUTHORIZED).send({ loggedIn: RESPONSE.LOGGED_OUT });
                return;
            }

            if (withJwt) {
                await jwtService.createJwtTokensAndSetCookies(user, res);
            } else {
                const session = await sessionService.createSession(user.userId);
                cookieService.setSessionCookie(res, session);
            }

            res.setHeader(HTTP_HEADERS.CONTENT_TYPE, HTTP_HEADERS.APPLICATION_JSON);
            res.status(HTTP_STATUS.OK).json({ loggedIn: RESPONSE.LOGGED_IN, username: user.username, count: user.count });
        } catch(error) {
            console.error(`${LOG_PREFIX.LOGIN} Login error`, error);
            res.status(HTTP_STATUS.INTERNAL_SERVER_ERROR).json({ loggedIn: RESPONSE.LOGGED_OUT });
        }
    });

    router.post(API_ROUTES.SIGNOUT, async (req, res) => {
        try {
            const { sessionId, refreshJwtToken } = req.cookies;
            if (!cookieService.cookieValuesExist(req.cookies)) {
                cookieService.clearCookie(res, COOKIE_NAMES.SESSION_ID);
                cookieService.clearCookie(res, COOKIE_NAMES.REFRESH_JWT_TOKEN);
                cookieService.clearCookie(res, COOKIE_NAMES.AUTH_JWT_TOKEN);
    
                res.status(HTTP_STATUS.UNAUTHORIZED).send();
                return;
            }
    
            if (cookieValueExists(refreshJwtToken)) {
                const secret = await getPrivateKey();
                try {
                    const payload = jwtService.verifyJwtToken(refreshJwtToken, secret);
                    const { userId } = payload;
                    await databaseService.updateRefreshTokenVersionForUser(userId)
                } catch (error) {
                    console.error(`${LOG_PREFIX.SIGNOUT} Error verifying refreshJWT or updating refresh_token_version`, error);
                    res.status(HTTP_STATUS.UNAUTHORIZED).send();
                }
    
                cookieService.clearCookie(res, COOKIE_NAMES.REFRESH_JWT_TOKEN);
                cookieService.clearCookie(res, COOKIE_NAMES.AUTH_JWT_TOKEN);
            }
    
            if (cookieValueExists(sessionId)) {
                const session = await databaseService.getSession(sessionId);
                if (!session) {
                    cookieService.clearCookie(res, COOKIE_NAMES.SESSION_ID);
                    res.status(HTTP_STATUS.UNAUTHORIZED).send();
                    return;
                }
    
                await databaseService.deleteSessionById(sessionId);
                cookieService.clearCookie(res, COOKIE_NAMES.SESSION_ID);
            }
    
            res.status(HTTP_STATUS.OK).send();
        } catch(error) {
            console.error(`${LOG_PREFIX.SIGNOUT} Error`, error);
            res.status(HTTP_STATUS.INTERNAL_SERVER_ERROR).send();
        }
    
    });

    return router;
}

module.exports = createAuthRoutes;