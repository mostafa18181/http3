const {Http3Response} = require('./response');
const Logger = require('../utils/logger');

const logger = new Logger({logLevel: 'info', logToFile: false});

function handleHttpRequest(stream, encryption) {
    let requestData = Buffer.alloc(0); // برای نگهداری داده‌های دریافتی

    stream.on('data', (chunk) => {
        requestData = Buffer.concat([requestData, chunk]);
    });

    stream.on('end', () => {
        const decryptedData = encryption.decrypt(requestData.toString(), encryption.iv.toString('hex'));
        logger.info(`Decrypted request data: ${decryptedData}`);
        const response = new Http3Response(stream, encryption);
        // پردازش درخواست و تنظیم پاسخ
        response.writeHead(200, {'Content-Type': 'text/plain'});
        response.end('Hello, HTTP/3!');
    });
}

module.exports = {handleHttpRequest};
