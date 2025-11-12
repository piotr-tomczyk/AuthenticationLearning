const { SESSIONS_TABLE_NAME } = require('./constants.js');
const { okAsync, errAsync } = require('neverthrow');
const { ERROR_TYPES } = require('./constants');

function areSessionParamsValid(session) {
    if(session && (typeof session.userid === 'string') && (typeof session.expiresat === 'object')) {
        return okAsync(true);
    } else {
        return errAsync({ type: ERROR_TYPES.SESSION_PARSE_ERROR, message: 'Error when parsing session response From' });
    }
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
