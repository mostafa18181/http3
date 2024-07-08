const dgram = require('dgram');
const {QuicConnection} = require('./connection');
const EventEmitter = require('events');

class QuicClient extends EventEmitter {
    constructor(options) {
        super();
        this.port = options.port || 4433;
        this.serverAddress = options.address || 'localhost';
        this.client = dgram.createSocket('udp4');
        this.connection = null;
        this.client.on('message', this.handleMessage.bind(this));
        this.encryption = options.encryption;
    }

    connect(callback) {
        // ایجاد اتصال جدید
        const rinfo = {address: this.serverAddress, port: this.port};
        this.connection = new QuicConnection(rinfo, this.client);
        this.connection.on('stream', (stream) => {
            this.emit('stream', stream);
        });
        callback(this.connection);
    }

    sendMessage(message, callback) {
        const encryptedMessage = this.encryption.encrypt(message).encryptedData;
        if (!this.connection) {
            this.connect(() => {
                this.connection.send(encryptedMessage);
                this.connection.on('data', (data) => {
                    const decryptedData = this.encryption.decrypt(data, this.encryption.iv.toString('hex'));
                    callback(decryptedData);
                });
            });
        } else {
            this.connection.send(encryptedMessage);
            this.connection.on('data', (data) => {
                const decryptedData = this.encryption.decrypt(data, this.encryption.iv.toString('hex'));
                callback(decryptedData);
            });
        }
    }

    handleMessage(msg, rinfo) {
        if (this.connection) {
            this.connection.handleMessage(msg);
        }
    }
}

module.exports = {QuicClient};
