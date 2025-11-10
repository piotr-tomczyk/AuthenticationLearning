const { cookieValueExists } = require('../utils/CookieUtils.js');
const { COOKIE_NAMES, COOKIE_SETTINGS, TIME } = require('../utils/constants.js');

class CookieService {
    cookieValuesExist(cookies) {
        const { sessionId, authJwtToken, refreshJwtToken } = cookies;
        return cookieValueExists(sessionId) || cookieValueExists(authJwtToken) || cookieValueExists(refreshJwtToken);
    }

    clearCookie(res, cookieName) {
        res.cookie(cookieName, null, {
            expires: 0,
            secure: COOKIE_SETTINGS.SECURE,
            httpOnly: COOKIE_SETTINGS.HTTP_ONLY,
            sameSite: COOKIE_SETTINGS.SAME_SITE,
        });
    }

    setSessionCookie(res, sessionId) {
        res.cookie(COOKIE_NAMES.SESSION_ID, sessionId, {
            expires: new Date(Date.now() + TIME.THIRTY_DAYS_MS),
            secure: COOKIE_SETTINGS.SECURE,
            httpOnly: COOKIE_SETTINGS.HTTP_ONLY,
            sameSite: COOKIE_SETTINGS.SAME_SITE,
        });
    }

    setRefreshJwtCookie(res, jwtToken) {
        res.cookie(COOKIE_NAMES.REFRESH_JWT_TOKEN, jwtToken, {
            expires: new Date(Date.now() + TIME.THIRTY_DAYS_MS),
            secure: COOKIE_SETTINGS.SECURE,
            httpOnly: COOKIE_SETTINGS.HTTP_ONLY,
            sameSite: COOKIE_SETTINGS.SAME_SITE,
        });
    }

    setAuthJwtCookie(res, jwtToken) {
        res.cookie(COOKIE_NAMES.AUTH_JWT_TOKEN, jwtToken, {
            expires: new Date(Date.now() + TIME.TWO_MINUTES_MS),
            secure: COOKIE_SETTINGS.SECURE,
            httpOnly: COOKIE_SETTINGS.HTTP_ONLY,
            sameSite: COOKIE_SETTINGS.SAME_SITE,
        });
    }
}

module.exports = CookieService;
