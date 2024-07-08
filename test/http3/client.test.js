const {expect} = require('chai');
const Http3Client = require('../../src/http3/client');
const Encryption = require('../../src/utils/encryption');
const nock = require('nock');

describe('Http3Client', () => {
    let client;
    let encryption;
    let key;
    let iv;

    before(() => {
        key = Encryption.generateKey();
        iv = Encryption.generateIv();
        encryption = new Encryption('aes-256-cbc', Buffer.from(key, 'hex'), Buffer.from(iv, 'hex'));
        const clientOptions = {
            port: 4433,
            address: 'localhost',
            encryption,
        };
        client = new Http3Client(clientOptions);
    });

    it('should send a GET request and receive a response', (done) => {
        // Mocking the server response
        const scope = nock(`http://localhost:4433`)
            .get('/')
            .reply(200, 'Hello, HTTP/3!');

        client.sendRequest({method: 'GET', path: '/'}, (headers, body) => {
            expect(body).to.equal('Hello, HTTP/3!');
            scope.done(); // Verify that all nocked endpoints have been reached
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
