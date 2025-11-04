const fs = require("node:fs/promises");
const PRIVATE_KEY_FILE_PATH = './private_key.pem';
const THIRTY_DAYS = '30d';
const ONE_MINUTE = '1m';
const DEFAULT_JWT_REFRESH_VERSION = '1';

async function getPrivateKey() {
    return fs.readFile(PRIVATE_KEY_FILE_PATH, { encoding: 'utf8' });
}

module.exports = {
    THIRTY_DAYS,
    ONE_MINUTE,
    DEFAULT_JWT_REFRESH_VERSION,
    getPrivateKey,
}
