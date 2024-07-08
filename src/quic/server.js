const dgram = require('dgram');
const {QuicConnection} = require('./connection');
const EventEmitter = require('events');

class QuicServer extends EventEmitter {
    constructor(options) {
        super();
        this.port = options.port || 4433;
        this.server = dgram.createSocket('udp4');
        this.server.on('message', this.handleMessage.bind(this));
        this.encryption = options.encryption;
    }

    handleMessage(msg, rinfo) {
        const connection = this.createConnection(rinfo);
        try {
            const decryptedMessage = this.encryption.decrypt(msg.toString(), this.encryption.iv.toString('hex'));
            connection.handleMessage(decryptedMessage);
        } catch (error) {
            console.error('failed:', error.message);
            return null;
        }

    }

    createConnection(rinfo) {
        const connection = new QuicConnection(rinfo, this.server);
        this.emit('session', connection);
        return connection;
    }

    listen(port, callback) {
        this.port = port || this.port;
        this.server.bind(this.port, callback);
    }
}

module.exports = {QuicServer};
