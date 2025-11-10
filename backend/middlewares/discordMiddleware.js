const DiscordStrategy = require('passport-discord').Strategy;
const { DISCORD, ERROR_MESSAGES, LOG_PREFIX } = require('../utils/constants.js');

function createRegisterDiscordAuthMiddleware(services, passport) {
    const { databaseService } = services;
    passport.use(new DiscordStrategy({
            clientID: process.env.DISCORD_CLIENT_ID,
            clientSecret: process.env.DISCORD_CLIENT_SECRET,
            callbackURL: DISCORD.CALLBACK_URL,
            scope: DISCORD.SCOPES
        },
        async function(accessToken, refreshToken, profile, cb) {
            try {
                const { id, username } = profile;
                if (!id || !username) {
                    return cb(new Error(ERROR_MESSAGES.INVALID_PROFILE));
                }

                const user = await databaseService.getUserById(profile.id);
                if (user) {
                    return cb(profile);
                }

                await databaseService.insertDiscordUser({ id, username });
                return cb(profile);
            } catch(error) {
                console.log(LOG_PREFIX.DISCORD_AUTH, error);
            }
    }));
}

module.exports = { createRegisterDiscordAuthMiddleware };