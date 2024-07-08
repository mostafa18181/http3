const Http3Server = require('../src/http3/server');
const Logger = require('../src/utils/logger');
const Encryption = require('../src/utils/encryption');

const logger = new Logger({logLevel: 'info', logToFile: true, logFilePath: './logs/server.log'});

// تولید کلید و IV تصادفی
const key = Encryption.generateKey();
const iv = Encryption.generateIv();
const encryption = new Encryption('aes-256-cbc', Buffer.from(key, 'hex'), Buffer.from(iv, 'hex'));

const serverOptions = {
    port: 4433,
    encryption,
};

const server = new Http3Server(serverOptions);

server.listen(serverOptions.port, () => {
    console.log(`HTTP/3 server is running on port ${serverOptions.port}`);
    console.log(`Encryption Key: ${key}`);
    console.log(`Encryption IV: ${iv}`);

    logger.info(`HTTP/3 server is running on port ${serverOptions.port}`);
    logger.info(`Encryption Key: ${key}`);
    logger.info(`Encryption IV: ${iv}`);
});
