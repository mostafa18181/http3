const dgram = require('dgram');
const crypto = require('crypto');
const forge = require('node-forge');
const fs = require('fs');

class HttpClient {
    constructor(address, port, publicKeyPath, privateKeyPath) {
        this.dataPublicKey = fs.readFileSync(publicKeyPath, 'utf8');
        this.dataPrivateKey = fs.readFileSync(privateKeyPath, 'utf8');
        this.address = address || 'localhost';
        this.udpPort = port || 4434;
        this.sessionId = null;
        this.udpClient = dgram.createSocket('udp4');
    }

    initializeSession() {
        return new Promise((resolve, reject) => {
            const nonce = crypto.randomBytes(16).toString('hex');
            const message = JSON.stringify({nonce, sessionId: null, data: 'HELLO'});
            const encryptedMessage = this.encryptMessage(message);

            this.udpClient.send(encryptedMessage, this.udpPort, this.address, (err) => {
                if (err) {
                    console.error('Error sending initial handshake:', err);
                    reject(err);
                } else {
                    console.log('Initial handshake message sent');
                }
            });

            this.udpClient.on('message', (msg, rinfo) => {
                const decryptedMsg = this.decryptMessage(msg.toString());
                console.log(`Received response from ${rinfo.address}:${rinfo.port}: ${decryptedMsg}`);

                try {
                    const response = JSON.parse(decryptedMsg);
                    if (response.type === 'handshake') {
                        this.sessionId = response.sessionId;
                        console.log(`Session ID received: ${this.sessionId}`);
                        resolve();
                    }
                } catch (error) {
                    console.error('Failed to parse response:', error);
                    reject(error);
                }
            });
        });
    }

    async sendHttpRequest(method, path, headers, body) {
        if (!this.sessionId) {
            console.error('No session ID. Initialize session first.');
            return;
        }

        const request = JSON.stringify({
            sessionId: this.sessionId,
            method,
            path,
            headers,
            body
        });

        console.log('Sending HTTP request:', request);

        await this.sendChunkedMessage(request, 1024);
    }

    async sendChunkedMessage(message, chunkSize) {
        let offset = 0;
        let chunkNumber = 0;
        const udpClient = this.udpClient;

        const sendChunk = (chunkNumber, chunk) => {
            return new Promise((resolve, reject) => {
                const packet = JSON.stringify({
                    sessionId: this.sessionId,
                    chunkNumber,
                    chunk,
                    totalChunks: Math.ceil(message.length / chunkSize)
                });
                const encryptedPacket = this.encryptMessage(packet);
                console.log("encryptedPacket---------" + packet);

                udpClient.send(encryptedPacket, this.udpPort, this.address, (err) => {
                    if (err) {
                        console.error(err);
                        reject(err);
                    } else {
                        console.log(`Chunk ${chunkNumber} sent`);
                        resolve();
                    }
                });
            });
        };

        const promises = [];

        while (offset < message.length) {
            const chunk = message.slice(offset, offset + chunkSize);
            promises.push(sendChunk(chunkNumber, chunk));
            offset += chunkSize;
            chunkNumber++;
        }

        await Promise.all(promises);
    }

    encryptMessage(message) {
        const aesKey = crypto.randomBytes(32);
        const iv = crypto.randomBytes(16);

        const cipher = crypto.createCipheriv('aes-256-gcm', aesKey, iv);
        let encrypted = cipher.update(message, 'utf8', 'hex');
        encrypted += cipher.final('hex');
        const authTag = cipher.getAuthTag().toString('hex');
        const encryptedMessage = iv.toString('hex') + ':' + encrypted + ':' + authTag;

        const publicKey = forge.pki.publicKeyFromPem(this.dataPublicKey);
        const encryptedKey = publicKey.encrypt(aesKey.toString('hex'), 'RSA-OAEP', {
            md: forge.md.sha256.create(),
            mgf1: forge.mgf.mgf1.create(forge.md.sha1.create())
        });

        return forge.util.encode64(encryptedKey) + ':' + encryptedMessage;
    }

    decryptMessage(encryptedData) {
        const parts = encryptedData.split(':');
        const [encryptedKeyBase64, iv, encrypted, authTag] = parts;

        if (parts.length !== 4) {
            console.error('Invalid encrypted data format');
            return '';
        }

        const privateKey = forge.pki.privateKeyFromPem(this.dataPrivateKey);
        const encryptedKey = forge.util.decode64(encryptedKeyBase64);
        const aesKeyHex = privateKey.decrypt(encryptedKey, 'RSA-OAEP', {
            md: forge.md.sha256.create(),
            mgf1: forge.mgf.mgf1.create(forge.md.sha1.create())
        });
        const aesKey = Buffer.from(aesKeyHex, 'hex');

        const decipher = crypto.createDecipheriv('aes-256-gcm', aesKey, Buffer.from(iv, 'hex'));
        decipher.setAuthTag(Buffer.from(authTag, 'hex'));
        let decrypted = decipher.update(encrypted, 'hex', 'utf8');
        decrypted += decipher.final('utf8');
        console.log("decrypted", decrypted);
        return decrypted;
    }
}

module.exports = HttpClient;
