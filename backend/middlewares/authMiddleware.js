const { cookieValueExists } = require('../utils/CookieUtils.js');
const { isSessionExpired } = require('../utils/SessionUtils.js');
const { HTTP_STATUS, RESPONSE, ERROR_MESSAGES, API_ROUTES } = require('../utils/constants.js');
const {ERROR_TYPES, LOG_PREFIX} = require("../utils/constants");

function createAuthenticateUserMiddleware(databaseService, jwtService, cookieService) {
    return async function authenticateUser(req, res, next) {
        const { sessionId, refreshJwtToken } = req.cookies;
        if (!cookieService.cookieValuesExist(req.cookies)) {
            res.json({
                loggedIn: RESPONSE.LOGGED_OUT,
            });
            return;
        }
        let userId;
        let user;

        if (cookieValueExists(sessionId)) {
            const sessionResult = await databaseService.getSession(sessionId);
            if (sessionResult.isErr()) {
                if (sessionResult.error.type === ERROR_TYPES.SQL_QUERY_ERROR) {
                    console.error(`${LOG_PREFIX.MIDDLEWARE_AUTH} Error making SQL query: ${sessionResult.error.query}`
                    + `, error: ${JSON.stringify(sessionResult.error.errors)}`);
                    res.json({
                        loggedIn: RESPONSE.LOGGED_OUT,
                    });
                    return;
                } else if (sessionResult.error.type === ERROR_TYPES.SESSION_PARSE_ERROR) {
                    console.error(`${LOG_PREFIX.MIDDLEWARE_AUTH} ${sessionResult.error.message}`);
                    res.json({
                        loggedIn: RESPONSE.LOGGED_OUT,
                    });
                    return;
                }
            }

            const session = sessionResult.value;

            if (isSessionExpired(session)) {
                res.json({
                    loggedIn: RESPONSE.LOGGED_OUT,
                })
                return;
            }

            userId = session.userId;
        } else if (cookieValueExists(refreshJwtToken)) {
            const handleRefreshTokenResponse = await jwtService.handleJwtTokenRefresh(
                res,
                refreshJwtToken,
                API_ROUTES.ME
            );

            if (handleRefreshTokenResponse.error) {
                if (handleRefreshTokenResponse.error.message === ERROR_MESSAGES.NO_VALID_PARAMS) {
                    res.status(HTTP_STATUS.NOT_FOUND).send();
                    return;
                } else {
                    res.status(HTTP_STATUS.UNAUTHORIZED).send();
                    return;
                }
            }
            user = handleRefreshTokenResponse.user;
            userId = handleRefreshTokenResponse.userId;
        } else {
            res.json({
                loggedIn: RESPONSE.LOGGED_OUT,
            })
            return;
        }

        if (!user) {
            user = await databaseService.getUserById(userId);
            if (!user) {
                res.status(HTTP_STATUS.NOT_FOUND).send();
                return;
            }
        }

        req.context = { user };

        next();
    }
}

module.exports = { createAuthenticateUserMiddleware };
