const {expect} = require('chai');
const Http3Server = require('../../src/http3/server');
const Http3Client = require('../../src/http3/client');
const Encryption = require('../../src/utils/encryption');
const Logger = require('../../src/utils/logger');
const nock = require('nock');
const http = require('http'); // فقط برای شبیه‌سازی

describe('Http3Server', () => {
    let server;
    let client;
    let encryption;
    let key;
    let iv;

    before((done) => {
        key = Encryption.generateKey();
        iv = Encryption.generateIv();
        encryption = new Encryption('aes-256-cbc', Buffer.from(key, 'hex'), Buffer.from(iv, 'hex'));

        const serverOptions = {
            port: 4433,
            encryption,
        };

        server = new Http3Server(serverOptions);

        server.listen(serverOptions.port, () => {
            const clientOptions = {
                port: 4433,
                address: 'localhost',
                encryption,
            };
            client = new Http3Client(clientOptions);
            done();
        });
    });

    after((done) => {
        server.quicServer.server.close(() => {
            done();
        });
    });

    it('should receive a GET request and send a response', (done) => {
        client.sendRequest({method: 'GET', path: '/'}, (headers, body) => {
            expect(body).to.equal('Hello, HTTP/3!');
            done();
        });
    });

    it('should properly encrypt and decrypt messages', () => {
        const message = 'This is a test message';
        const encrypted = encryption.encrypt(message);
        const decrypted = encryption.decrypt(encrypted.encryptedData, encrypted.iv);

        expect(decrypted).to.equal(message);
    });
});
