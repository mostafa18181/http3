const {QuicServer} = require('../quic/server');
const {handleHttpRequest} = require('./request');
const Logger = require('../utils/logger');

const logger = new Logger({logLevel: 'info', logToFile: true, logFilePath: './logs/server.log'});

class Http3Server {
    constructor(options) {
        this.quicServer = new QuicServer(options);
        this.quicServer.on('session', this.handleSession.bind(this));
        this.encryption = options.encryption;
    }

    handleSession(session) {
        session.on('stream', (stream) => {
            stream.on('data', (data) => {
                console.log(`Received data: ${data}`)
                const decryptedData = this.encryption.decrypt(data.toString(), this.encryption.iv.toString('hex'));
                console.log(`Decrypted data: ${decryptedData}`)

                logger.info('Received decrypted data: ' + decryptedData);
                handleHttpRequest(stream, this.encryption);
            });
        });
    }

    listen(port, callback) {
        this.quicServer.listen(port, callback);
    }
}

module.exports = Http3Server;
