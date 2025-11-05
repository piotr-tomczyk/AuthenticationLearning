const crypto = require('node:crypto');
const { THIRTY_DAYS } = require('../utils/SessionUtils.js');

class SessionService {
    constructor(databaseService) {
        this.databaseService = databaseService;
    }

    async createSession(userId) {
        await this.databaseService.deleteExpiredSessions();
        const sessionId = crypto.randomUUID();
        await this.databaseService.insertSession({ sessionId, userId , expiresAt: (Date.now() + THIRTY_DAYS) })
        return sessionId;
    }
}

module.exports = SessionService;
