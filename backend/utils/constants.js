// SERVER CONFIGURATION

const SERVER_PORT = 3000;
const FRONTEND_URL = 'http://localhost:5173';
const FRONTEND_PORT = 5173;
const BACKEND_URL = 'http://localhost:3000';

// DATABASE CONFIGURATION
const DB_CONNECTION_STRING = process.env.DB_CONNECTION_STRING || 'postgres://postgres:admin@localhost:5432/auth';
const SESSIONS_TABLE_NAME = 'auth.public.sessions';

const COOKIE_NAMES = {
    SESSION_ID: 'sessionId',
    AUTH_JWT_TOKEN: 'authJwtToken',
    REFRESH_JWT_TOKEN: 'refreshJwtToken',
};

const COOKIE_SETTINGS = {
    HTTP_ONLY: true,
    SAME_SITE: 'strict',
    SECURE: false, // Should be true in production with HTTPS
};

// TIME DURATIONS (in milliseconds unless specified)
const TIME = {
    ONE_SECOND: 1000,
    ONE_MINUTE_MS: 1000 * 60,
    TWO_MINUTES_MS: 1000 * 60 * 2,
    ONE_HOUR_MS: 1000 * 60 * 60,
    ONE_DAY_MS: 1000 * 60 * 60 * 24,
    THIRTY_DAYS_MS: 1000 * 60 * 60 * 24 * 30,
    
    // JWT expiration strings
    ONE_MINUTE: '1m',
    THIRTY_DAYS: '30d',
};

// Alternative for session utils (in seconds)
const TIME_SECONDS = {
    ONE_DAY: 3600 * 24,
    THIRTY_DAYS: 3600 * 24 * 30,
};

// JWT CONFIGURATION
const JWT = {
    ALGORITHM: 'RS256',
    DEFAULT_REFRESH_VERSION: '1',
    PRIVATE_KEY_FILE_PATH: './private_key.pem',
};

const API_ROUTES = {
    ME: '/api/me',
    REGISTER: '/api/register',
    LOGIN: '/api/login',
    SIGNOUT: '/api/signout',
    INCREMENT: '/api/increment',
    LOGIN_DISCORD: '/api/login/discord',
    DISCORD_CALLBACK: '/api/discord/callback',
};

const HTTP_STATUS = {
    OK: 200,
    CREATED: 201,
    BAD_REQUEST: 400,
    UNAUTHORIZED: 401,
    NOT_FOUND: 404,
    INTERNAL_SERVER_ERROR: 500,
};

const HTTP_HEADERS = {
    CONTENT_TYPE: 'Content-Type',
    APPLICATION_JSON: 'application/json',
};

// DISCORD CONFIGURATION
const DISCORD = {
    SCOPES: ['identify', 'email'],
    CALLBACK_URL: `${BACKEND_URL}/api/discord/callback`,
    FAILURE_REDIRECT: '/',
};

const ERROR_MESSAGES = {
    NO_VALID_PARAMS: 'no_valid_params',
    NO_VERSION_MATCH: 'no_version_match',
    UNKNOWN_ERROR: 'unknown_error',
    INVALID_PROFILE: 'Invalid profile, id or username is missing',
};

const LOG_PREFIX = {
    REGISTER: 'api/register',
    LOGIN: 'api/login',
    SIGNOUT: 'api/signout',
    INCREMENT: 'api/increment',
    DISCORD_AUTH: 'Error authenticating with discord',
};

const RESPONSE = {
    LOGGED_IN: true,
    LOGGED_OUT: false,
    INITIAL_COUNT: 0,
};

const CORS_CONFIG = {
    origin: FRONTEND_URL,
    credentials: true,
};

module.exports = {
    // Server
    SERVER_PORT,
    FRONTEND_URL,
    FRONTEND_PORT,
    BACKEND_URL,
    
    // Database
    DB_CONNECTION_STRING,
    SESSIONS_TABLE_NAME,
    
    // Cookies
    COOKIE_NAMES,
    COOKIE_SETTINGS,
    
    // Time
    TIME,
    TIME_SECONDS,
    
    // JWT
    JWT,
    
    // Routes
    API_ROUTES,
    
    // HTTP
    HTTP_STATUS,
    HTTP_HEADERS,
    
    // Discord
    DISCORD,
    
    // Errors
    ERROR_MESSAGES,
    
    // Logs
    LOG_PREFIX,
    
    // Response
    RESPONSE,
    
    // CORS
    CORS_CONFIG,
};

