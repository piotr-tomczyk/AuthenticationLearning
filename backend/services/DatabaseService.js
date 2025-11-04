const { areSessionParamsValid, mapDatabaseSession, SESSIONS_TABLE_NAME } = require('../utils/SessionUtils');
const { areUserParamsValid, mapDatabaseUser, USERS_TABLE_NAME } = require('../utils/UserUtils');
const crypto = require('node:crypto');

class DatabaseService {
    constructor(sqlClient) {
        this.client = sqlClient;
    }

    async queryDatabase(query, variables) {
        const response = await this.client.query(query, variables);
        return response?.rows?.[0];
    }

    async getSession(sessionId) {
        const sessionResponse = await this.queryDatabase(`SELECT * FROM ${SESSIONS_TABLE_NAME} WHERE sessionid = $1`, [sessionId]);
        if (!areSessionParamsValid(sessionResponse)) {
            return null;
        }
        const session = mapDatabaseSession(sessionResponse);
        return session;
    }

    async getUserById(userId) {
        const userResponse = await this.queryDatabase(
            `SELECT * FROM ${USERS_TABLE_NAME} WHERE userid = $1`,
            [userId]
        );
        if (!areUserParamsValid(userResponse)) {
            return null;
        }

        return mapDatabaseUser(userResponse);
    }

    async getUserByUsername(username) {
        const userResponse = await this.queryDatabase(
            `SELECT * FROM ${USERS_TABLE_NAME} WHERE userid = $1`,
            [username]
        );
        if (!areUserParamsValid(userResponse)) {
            return null;
        }

        return mapDatabaseUser(userResponse);
    }

    async getNonDiscordUserByUsername(username) {
        const userResponse = await this.queryDatabase(
            `SELECT * FROM ${USERS_TABLE_NAME} WHERE username = $1 AND login_type != $2`,
            [username, 'discord']
        );

        if (!areUserParamsValid(userResponse)) {
            return null;
        }

        return mapDatabaseUser(userResponse);
    }

    async insertUser(params) {
        const { userId, username, hashedPassword } = params;
        return this.queryDatabase(
            `INSERT INTO ${USERS_TABLE_NAME} (userid, username, password) VALUES ($1, $2, $3)`,
            [userId, username, hashedPassword]
        );
    }

    async updateRefreshTokenVersionForUser(userId) {
        const newRefreshTokenVersion = crypto.randomUUID();
        return this.queryDatabase(
            `UPDATE ${USERS_TABLE_NAME} SET refresh_jwt_version = $1 WHERE userid = $2;`,
            [newRefreshTokenVersion, userId]
        );
    }


    async increaseUserCountProperty(userId) {
        return this.queryDatabase(
            `UPDATE ${USERS_TABLE_NAME} SET count = count + 1 WHERE userid=$1 RETURNING count`,
            [userId]
        );
    }


    async insertSession(params) {
        const { sessionId, userId, expiresAt, } = params;
        return this.queryDatabase(
            `INSERT INTO ${SESSIONS_TABLE_NAME} (sessionid, userid, expiresat) VALUES ($1, $2, to_timestamp($3))`,
            [sessionId, userId, Math.floor(expiresAt)],
        );
    }

    async deleteSessionById(sessionId) {
        return this.queryDatabase(`DELETE FROM ${SESSIONS_TABLE_NAME} WHERE sessionid=$1`, [sessionId]);
    }

    async deleteExpiredSessions() {
        return this.queryDatabase(
            `DELETE FROM ${SESSIONS_TABLE_NAME} WHERE expiresat<to_timestamp($1)`,
            [Math.floor(Date.now() / 1000)]
        );
    }
}

module.exports = DatabaseService;
