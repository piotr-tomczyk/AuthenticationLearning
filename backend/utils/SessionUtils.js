const { SESSIONS_TABLE_NAME } = require('./constants.js');

function areSessionParamsValid(session) {
    return session && (typeof session.userid === 'string') && (typeof session.expiresat === 'object');
}

function mapDatabaseSession(session) {
    return {
        sessionId: session.sessionid,
        userId: session.userid,
        expiresAt: session.expiresat,
    }
}

function isSessionExpired(session) {
    return session.expiresAt?.getTime() < Date.now();
}

module.exports = {
    areSessionParamsValid,
    mapDatabaseSession,
    isSessionExpired,
    SESSIONS_TABLE_NAME,
};
