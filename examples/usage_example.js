const {Http3Server, Http3Client, Logger, Encryption} = require('../src');

// تنظیمات سرور و کلاینت
const logger = new Logger({logLevel: 'info', logToFile: true, logFilePath: './logs/example.log'});
const key = Encryption.generateKey();
const iv = Encryption.generateIv();
const encryption = new Encryption('aes-256-cbc', Buffer.from(key, 'hex'), Buffer.from(iv, 'hex'));

// سرور HTTP/3
const serverOptions = {
    port: 4433,
    encryption,
};
const server = new Http3Server(serverOptions);

server.listen(serverOptions.port, () => {
    logger.info(`HTTP/3 server is running on port ${serverOptions.port}`);
    logger.info(`Encryption Key: ${key}`);
    logger.info(`Encryption IV: ${iv}`);
});

// کلاینت HTTP/3
const clientOptions = {
    port: 4433,
    address: 'localhost',
    encryption,
};
const client = new Http3Client(clientOptions);

client.sendRequest({method: 'GET', path: '/'}, (headers, body) => {
    logger.info('Response Headers: ' + headers);
    logger.info('Response Body: ' + body);
});
