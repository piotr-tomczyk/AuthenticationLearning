const jwt = require('jsonwebtoken');
const { ONE_MINUTE, THIRTY_DAYS, DEFAULT_JWT_REFRESH_VERSION, getPrivateKey } = require('../utils/JwtUtils.js');

class JwtService {
    constructor(databaseService, cookieService) {
        this.databaseService = databaseService;
        this.cookieService = cookieService;
    }

    async handleJwtTokenRefresh(res, refreshJwtToken, errorPrefix) {
        const secret = await getPrivateKey();
        const returnData = {
            userId: null,
            user: null,
            error: null,
        };

        try {
            const payload = jwt.verify(refreshJwtToken, secret);
            returnData.userId = payload.userId;
            const user = await this.databaseService.getUserById(payload.userId);
            if (!user) {
                returnData.error = {
                    message: 'no_valid_params',
                };
                return returnData;
            }

            returnData.user = user;

            if (returnData.user.refreshJwtVersion !== payload?.version) {
                console.error(`[${errorPrefix}] Refresh JWT version doesnt match`);
                returnData.error = {
                    message: 'no_version_match',
                };
                return returnData;
            } else {
                const authJwtToken = await this.createJwt(returnData.userId);
                this.cookieService.setAuthJwtCookie(res, authJwtToken);
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

    async createJwtTokensAndSetCookies(params, res) {
        const { userId, refreshTokenVersion } = params;
        const authJwtToken = await this.createJwt(userId);
        const refreshJwtToken = await this.createRefreshJwt(userId, refreshTokenVersion);

        this.cookieService.setAuthJwtCookie(res, authJwtToken)
        this.cookieService.setRefreshJwtCookie(res, refreshJwtToken);
    }



    async createJwt(userId) {
        const payload = {
            userId,
        };
        const secret = await getPrivateKey();
        const jwtToken = jwt.sign(payload, secret, { algorithm: 'RS256', expiresIn: ONE_MINUTE });
        return jwtToken;
    }

    async createRefreshJwt(userId, version = DEFAULT_JWT_REFRESH_VERSION) {
        const payload = {
            userId,
            version,
        };
        const secret = await getPrivateKey();
        const jwtToken = jwt.sign(payload, secret, { algorithm: 'RS256', expiresIn: THIRTY_DAYS });
        return jwtToken;
    }

    verifyJwtToken(jwtToken, secret) {
        return jwt.verify(jwtToken, secret);
    }
}

module.exports = JwtService;
