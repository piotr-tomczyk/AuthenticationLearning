const express = require('express');
const { 
    API_ROUTES, 
    HTTP_STATUS, 
    DISCORD, 
    FRONTEND_URL 
} = require('../utils/constants.js');

const createDiscordRoutes = (app, services, passport) => {
    const router = express.Router();
    const {
        cookieService, 
        sessionService, 
    } = services;
    
    router.get(API_ROUTES.LOGIN_DISCORD, passport.authenticate('discord'), async (req, res) => {
        res.status(HTTP_STATUS.OK).send();
    });
    
    router.get(API_ROUTES.DISCORD_CALLBACK, (req, res, next) => {
        passport.authenticate('discord', { failureRedirect: DISCORD.FAILURE_REDIRECT }, async (user) => {
            const session = await sessionService.createSession(user.id);
            cookieService.setSessionCookie(res, session);
    
            res.redirect(FRONTEND_URL);
        })(req, res, next);
    });

    return router;
}

module.exports = createDiscordRoutes;