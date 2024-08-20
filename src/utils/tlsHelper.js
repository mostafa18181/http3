const fs = require('fs');

function getTLSOptions(config) {
    return {
        key: fs.readFileSync(config.key),
        cert: fs.readFileSync(config.cert),
        ca: fs.readFileSync(config.ca),
        requestCert: config.requestCert,
        rejectUnauthorized: config.rejectUnauthorized
    };
}

module.exports = {getTLSOptions};
