function cookieValueExists(cookieValue) {
    return cookieValue && cookieValue !== 'j:null';
}

module.exports = {
    cookieValueExists,
}
