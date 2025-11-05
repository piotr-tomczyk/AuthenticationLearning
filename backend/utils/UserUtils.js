const USERS_TABLE_NAME = 'auth.public.users';

function mapDatabaseUser(user) {
    return {
        userId: user.userid,
        username: user.username,
        password: user.password,
        count: user.count,
        loginType: user.login_type,
        refreshJwtVersion: user.refresh_jwt_version,
    }
}

function areUserParamsValid(user) {
    return user && (typeof user.username === 'string') && (typeof user.password === 'string') && (typeof user.count === 'number') && (typeof user.login_type === 'string') && (typeof user.refresh_jwt_version === 'string');
}

module.exports = {
    mapDatabaseUser,
    areUserParamsValid,
    USERS_TABLE_NAME,
};
