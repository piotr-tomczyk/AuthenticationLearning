const express = require('express')
const app = express()
const cors = require('cors');
const pg = require('pg');
const cookieParser = require("cookie-parser");
const passport = require('passport');
require('dotenv').config();
const { SERVER_PORT, DB_CONNECTION_STRING, CORS_CONFIG } = require('./utils/constants.js');
const DatabaseService = require('./services/DatabaseService.js');
const CookieService = require('./services/CookieService.js');
const JwtService = require('./services/JwtService.js');
const SessionService = require('./services/SessionService.js');
const UserService = require('./services/UserService.js');
const PasswordService = require('./services/PasswordService.js');
const { createAuthenticateUserMiddleware } = require('./middlewares/authMiddleware.js');
const { createRegisterDiscordAuthMiddleware } = require('./middlewares/discordMiddleware.js');
const createAuthRoutes = require('./routes/authRoutes.js');
const createDiscordRoutes = require('./routes/discordRoutes.js');
const createIncrementRoutes = require('./routes/incrementRoutes.js');

const client = new pg.Client(DB_CONNECTION_STRING);
client.connect();
const databaseService = new DatabaseService(client);
const cookieService = new CookieService();
const jwtService = new JwtService(databaseService, cookieService)
const sessionService = new SessionService(databaseService);
const passwordService = new PasswordService();
const userService = new UserService(databaseService, passwordService);

const services = {
    databaseService,
    cookieService,
    jwtService,
    sessionService,
    passwordService,
    userService,
};

const authenticateUser = createAuthenticateUserMiddleware(databaseService, jwtService, cookieService);
createRegisterDiscordAuthMiddleware(services, passport);

const authRoutes = createAuthRoutes(app, services, authenticateUser);
const discordRoutes = createDiscordRoutes(app, services, passport);
const incrementRoutes = createIncrementRoutes(app, services, authenticateUser);

app.use(express.json());
app.use(cookieParser());
app.use(cors(CORS_CONFIG));

app.use(authRoutes);
app.use(discordRoutes);
app.use(incrementRoutes);


app.listen(SERVER_PORT, () => {
  console.log(`Example app listening on port ${SERVER_PORT}`)
})

