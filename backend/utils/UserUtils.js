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
    return user && user.username && user.password && user.count && user.login_type && user.refresh_jwt_version;
}

module.exports = {
    mapDatabaseUser,
    areUserParamsValid,
    USERS_TABLE_NAME,
};
