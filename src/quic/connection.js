const dgram = require('dgram');
const EventEmitter = require('events');

class QuicConnection extends EventEmitter {
    constructor(rinfo, server) {
        super();
        this.rinfo = rinfo;
        this.server = server;
        this.streams = {};
        this.nextStreamId = 0;
    }

    handleMessage(msg) {
        const buffer = Buffer.from(msg); // تبدیل msg به یک بافر
        const streamId = this.extractStreamId(buffer);
        if (!this.streams[streamId]) {
            this.streams[streamId] = this.createStream(streamId);
        }
        this.streams[streamId].handleMessage(buffer);
    }

    extractStreamId(buffer) {
        // استخراج شناسه جریان از بافر
        return buffer.readUInt16BE(0);
    }

    createStream(streamId) {
        const stream = new QuicStream(this, streamId);
        this.emit('stream', stream);
        return stream;
    }

    send(msg) {
        const message = Buffer.from(msg);
        this.server.send(message, 0, message.length, this.rinfo.port, this.rinfo.address);
    }
}

class QuicStream extends EventEmitter {
    constructor(connection, streamId) {
        super();
        this.connection = connection;
        this.streamId = streamId;
        this.buffer = '';
    }

    handleMessage(buffer) {
        // مدیریت پیام‌های ورودی برای جریان
        this.buffer += buffer.toString();
        this.emit('data', buffer.toString());
    }

    write(data) {
        const message = Buffer.from(data);
        this.connection.send(message);
    }

    end() {
        this.emit('end');
    }
}

module.exports = {QuicConnection, QuicStream};
