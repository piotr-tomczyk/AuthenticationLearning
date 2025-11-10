const express = require('express');
const { API_ROUTES, HTTP_STATUS, LOG_PREFIX } = require('../utils/constants.js');

const createIncrementRoutes = (app, services, authenticateUser) => {
    const router = express.Router();
    const { databaseService } = services;
    
    router.patch(API_ROUTES.INCREMENT, authenticateUser, async (req, res) => {
        const { user } = req.context;
        try {
            const count = await databaseService.increaseUserCountProperty(user.userId);
    
            res.status(HTTP_STATUS.OK).send({
                count: count?.count,
            });
        } catch(error) {
            console.error(`${LOG_PREFIX.INCREMENT} Increment error`, error);
            res.status(HTTP_STATUS.INTERNAL_SERVER_ERROR).send({
                count: null,
            });
        }
    });

    return router;
}

module.exports = createIncrementRoutes;