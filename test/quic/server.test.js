const {expect} = require('chai');
const {QuicClient} = require('../../src/quic/client');
const {QuicServer} = require('../../src/quic/server');
const Encryption = require('../../src/utils/encryption');
const Logger = require('../../src/utils/logger');

describe('QuicServer', () => {
    let client;
    let server;
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

        server = new QuicServer(serverOptions);
        server.on('session', (session) => {
            session.on('stream', (stream) => {
                stream.on('data', (data) => {
                    const decryptedData = encryption.decrypt(data.toString(), encryption.iv.toString('hex'));
                    const response = encryption.encrypt('Hello, QUIC Client!');
                    stream.write(response.encryptedData);
                });
            });
        });

        server.listen(serverOptions.port, () => {
            const clientOptions = {
                port: 4433,
                address: 'localhost',
                encryption,
            };
            client = new QuicClient(clientOptions);
            done();
        });
    });

    after((done) => {
        server.server.close(() => {
            done();
        });
    });

    it('should receive a message and send a response', (done) => {
        const message = 'Hello, QUIC Server!';
        const encryptedMessage = encryption.encrypt(message);

        client.sendMessage(encryptedMessage.encryptedData, (response) => {
            const decryptedResponse = encryption.decrypt(response, encryptedMessage.iv);
            expect(decryptedResponse).to.equal('Hello, QUIC Client!');
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
