const fs = require('fs');
const path = require('path');

class Logger {
    constructor(options = {}) {
        this.logLevel = options.logLevel || 'info';
        this.logToFile = options.logToFile || false;
        this.logFilePath = options.logFilePath || path.join(__dirname, 'logs', 'app.log');

        if (this.logToFile) {
            fs.mkdirSync(path.dirname(this.logFilePath), {recursive: true});
        }
    }

    log(level, message) {
        const logMessage = `[${new Date().toISOString()}] [${level.toUpperCase()}] ${message}`;

        if (this.logToFile) {
            fs.appendFileSync(this.logFilePath, logMessage + '\n', {encoding: 'utf8'});
        } else {
            console.log(logMessage);
        }
    }

    info(message) {
        if (this.shouldLog('info')) {
            this.log('info', message);
        }
    }

    warn(message) {
        if (this.shouldLog('warn')) {
            this.log('warn', message);
        }
    }

    error(message) {
        if (this.shouldLog('error')) {
            this.log('error', message);
        }
    }

    shouldLog(level) {
        const levels = ['error', 'warn', 'info'];
        return levels.indexOf(level) <= levels.indexOf(this.logLevel);
    }
}

module.exports = Logger;
