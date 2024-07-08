const {QuicClient} = require('../quic/client');

class Http3Client {
    constructor(options) {
        this.quicClient = new QuicClient(options);
        this.encryption = options.encryption;
    }

    sendRequest({method, path}, callback) {
        const request = `${method} ${path} HTTP/3.0\r\n\r\n`;
        const encryptedRequest = this.encryption.encrypt(request);
        this.quicClient.sendMessage(encryptedRequest.encryptedData, (response) => {
            const decryptedResponse = this.encryption.decrypt(response, encryptedRequest.iv);
            const [headers, body] = decryptedResponse.split('\r\n\r\n');
            callback(headers, body);
        });
    }
}

module.exports = Http3Client;
