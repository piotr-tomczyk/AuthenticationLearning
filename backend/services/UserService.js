const crypto = require("node:crypto");

class UserService {
    constructor(databaseService, passwordService) {
        this.databaseService = databaseService;
        this.passwordService = passwordService;
    }

    async createUserWithPassword(username, password) {
        const hashedPassword = await  this.passwordService.generatePassword(password);
        const userId = crypto.randomUUID();
        await this.databaseService.insertUser({ userId, username, hashedPassword });
        return userId;
    }
}

module.exports = UserService;
