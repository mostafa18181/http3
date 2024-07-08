const Http3Client = require('../src/http3/client');
const Logger = require('../src/utils/logger');
const Encryption = require('../src/utils/encryption');

const logger = new Logger({logLevel: 'info', logToFile: true, logFilePath: './logs/client.log'});

// استفاده از کلید و IV سرور برای رمزنگاری
const key = '447e22a1d858b3ab07d7aad93bafef596d582f983af65a87ef97ec2b30ad8551';
const iv = '0eec586956e8b952c27c1e75615632ca';
const encryption = new Encryption('aes-256-cbc', Buffer.from(key, 'hex'), Buffer.from(iv, 'hex'));

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
