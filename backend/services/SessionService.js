const crypto = require('node:crypto');
const { TIME_SECONDS } = require('../utils/constants.js');

class SessionService {
    constructor(databaseService) {
        this.databaseService = databaseService;
    }

    async createSession(userId) {
        await this.databaseService.deleteExpiredSessions();
        const sessionId = crypto.randomUUID();
        await this.databaseService.insertSession({ sessionId, userId , expiresAt: (Date.now() + TIME_SECONDS.THIRTY_DAYS) })
        return sessionId;
    }
}

module.exports = SessionService;
