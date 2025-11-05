const { cookieValueExists } = require('../utils/CookieUtils.js');

class CookieService {
    cookieValuesExist(cookies) {
        const { sessionId, authJwtToken, refreshJwtToken } = cookies;
        return cookieValueExists(sessionId) || cookieValueExists(authJwtToken) || cookieValueExists(refreshJwtToken);
    }

    clearCookie(res, cookieName) {
        res.cookie(cookieName, null, {
            expires: 0,
            secure: false,
            httpOnly: true,
            sameSite: 'strict',
        });
    }

    setSessionCookie(res, sessionId) {
        res.cookie('sessionId', sessionId, {
            expires: new Date(Date.now() + 1000 * 3600 * 24 * 30),
            secure: false,
            httpOnly: true,
            sameSite: 'strict',
        });
    }

    setRefreshJwtCookie(res, jwtToken) {
        res.cookie('refreshJwtToken', jwtToken, {
            expires: new Date(Date.now() + 1000 * 60 * 60 * 24 * 30),
            secure: false,
            httpOnly: true,
            sameSite: 'strict',
        });
    }

    setAuthJwtCookie(res, jwtToken) {
        res.cookie('authJwtToken', jwtToken, {
            expires: new Date(Date.now() + 1000 * 60 * 2),
            secure: false,
            httpOnly: true,
            sameSite: 'strict',
        });
    }
}

module.exports = CookieService;
