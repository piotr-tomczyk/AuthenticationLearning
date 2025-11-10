const fs = require('node:fs/promises');
const { JWT } = require('./constants.js');

async function getPrivateKey() {
    return fs.readFile(JWT.PRIVATE_KEY_FILE_PATH, { encoding: 'utf8' });
}

module.exports = {
    getPrivateKey,
}
