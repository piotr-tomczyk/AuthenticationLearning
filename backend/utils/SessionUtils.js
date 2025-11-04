const SESSIONS_TABLE_NAME = 'auth.public.sessions';
const ONE_DAY = 3600 * 24;
const THIRTY_DAYS = ONE_DAY * 30;

function areSessionParamsValid(session) {
    return session && session.userid && session.expiresat;
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
    THIRTY_DAYS,
};
