const bcrypt = require('bcrypt');

class PasswordService {
    async generatePassword(password) {
        const saltRounds = 10;
        return bcrypt.hash(password, saltRounds);
    }

    validatePassword(password, hash) {
        return bcrypt.compare(password, hash);
    }
}

module.exports = PasswordService;
