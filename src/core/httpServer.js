const dgram = require('dgram');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const os = require('os');
const forge = require('node-forge');

const SESSION_TIMEOUT = 300000; // 5 minutes

class HttpServer {
    constructor(address, port, publicKeyPath, privateKeyPath) {
        this.dataPublicKey = fs.readFileSync(publicKeyPath, 'utf8');
        this.dataprivateKey = fs.readFileSync(privateKeyPath, 'utf8');
        this.sessions = new Map();
        this.nonceSet = new Set();
        this.nonceTTL = 60000;
        this.maxConcurrentRequests = 10;
        this.requestQueue = [];
        this.activeRequests = 0;
        this.maxWindowSize = 1024 * 1024;
        this.currentWindowSize = 0;
        this.address = address || 'localhost';
        this.udpPort = port || 4434;
        this.chunkStore = new Map();
        this.tempDir = path.join(os.tmpdir(), 'http3server');
        fs.mkdirSync(this.tempDir, {recursive: true});
        this.udpResponseSocket = dgram.createSocket('udp4');
        this.routes = [];
        this.setupUDPServer();
    }

    setupUDPServer() {
        this.udpServer = dgram.createSocket('udp4');
        console.log("UDP server setup started");

        this.udpServer.on('message', async (msg, rinfo) => {
            console.log(`UDP server received: ${msg} from ${rinfo.address}:${rinfo.port}`);

            const decryptedMsg = this.decryptMessage(msg.toString());

            if (!decryptedMsg) {
                console.log('Decrypted message is invalid, dropping packet');
                return;
            }

            const {nonce, sessionId, data, chunkNumber, chunk, totalChunks} = this.parseMessage(decryptedMsg);

            if (this.isReplayAttack(nonce)) {
                console.log('Replay attack detected');
                return;
            }

            this.addNonce(nonce);
            console.log("data", data);
            if (data && data.startsWith('HELLO')) {
                this.handleInitialHandshake(rinfo, data);
            } else {
                if (!this.sessions.has(sessionId)) {
                    console.log('Invalid session ID, dropping packet');
                    return;
                }

                if (this.currentWindowSize + (chunk ? chunk.length : (data ? data.length : 0)) > this.maxWindowSize) {
                    console.log('Window size exceeded, dropping data');
                    return;
                }
                this.currentWindowSize += (chunk ? chunk.length : (data ? data.length : 0));

                if (chunk !== undefined && chunkNumber !== undefined && totalChunks !== undefined) {
                    this.storeChunkInMemory(chunkNumber, chunk, totalChunks, rinfo, sessionId);
                } else {
                    if (data) {
                        await this.handleRequest(rinfo, data, sessionId);
                    } else {
                        console.log('Received undefined data, dropping packet');
                    }
                }
            }
        });

        this.udpServer.on('error', (err) => {
            console.log(`UDP server error: ${err.stack}`);
            this.udpServer.close();
        });

        this.udpServer.bind(this.udpPort, this.address, () => {
            console.log(`UDP server listening on ${this.address}:${this.udpPort}`);
        });
    }

    setRequestHandler(handler) {
        this.requestHandler = handler;
    }

    async handleRequest(rinfo, data, sessionId) {
        if (this.activeRequests >= this.maxConcurrentRequests) {
            this.requestQueue.push({rinfo, data, sessionId});
            console.log('Request added to queue');
            return;
        }

        this.activeRequests++;
        try {
            const request = JSON.parse(data);
            console.log('Parsed request:', request);

            if (this.requestHandler) {
                const response = await this.requestHandler(request, sessionId);
                console.log('Generated response:', response);

                const encryptedResponse = this.encryptMessage(JSON.stringify(response));
                this.udpResponseSocket.send(encryptedResponse, rinfo.port, rinfo.address, (err) => {
                    if (err) console.error('Error sending response:', err);
                    else console.log('Response sent successfully');
                });
            } else {
                console.log('No request handler set');
            }
        } catch (error) {
            console.error('Error handling request:', error);
        } finally {
            this.activeRequests--;
            if (this.requestQueue.length > 0) {
                const nextRequest = this.requestQueue.shift();
                this.handleRequest(nextRequest.rinfo, nextRequest.data, nextRequest.sessionId);
            }
        }
    }

    parseMessage(msg) {
        try {
            const parsed = JSON.parse(msg.toString());

            return {
                nonce: parsed.nonce,
                sessionId: parsed.sessionId,
                data: parsed.data,
                chunkNumber: parsed.chunkNumber,
                chunk: parsed.chunk ? Buffer.from(parsed.chunk) : undefined,
                totalChunks: parsed.totalChunks
            };
        } catch (error) {
            console.error('Failed to parse message:', error);
            return {nonce: null, sessionId: null, data: null};
        }
    }

    isReplayAttack(nonce) {
        return this.nonceSet.has(nonce);
    }

    addNonce(nonce) {
        this.nonceSet.add(nonce);
        setTimeout(() => {
            this.nonceSet.delete(nonce);
        }, this.nonceTTL);
    }

    handleInitialHandshake(rinfo, data) {
        console.log('Handling initial handshake');

        const sessionId = crypto.randomBytes(16).toString('hex');
        this.sessions.set(sessionId, {publicKey: this.dataPublicKey, privateKey: this.dataprivateKey});

        setTimeout(() => {
            this.sessions.delete(sessionId);
        }, SESSION_TIMEOUT);

        const response = JSON.stringify({type: 'handshake', publicKey: this.dataPublicKey, sessionId});
        const encryptedResponse = this.encryptMessage(response);

        this.udpResponseSocket.send(encryptedResponse, rinfo.port, rinfo.address, (err) => {
            if (err) console.error(err);
        });

        console.log('Sent public key for handshake');
    }

    storeChunkInMemory(chunkNumber, chunk, totalChunks, rinfo, sessionId) {
        const address = rinfo.address + ':' + rinfo.port;
        if (!this.chunkStore.has(address)) {
            this.chunkStore.set(address, {totalChunks, chunks: [], sessionId});
        }

        const chunkData = this.chunkStore.get(address);
        chunkData.chunks[chunkNumber] = chunk;
        console.log(`Stored chunk ${chunkNumber} for ${address}`);

        if (chunkData.chunks.filter(c => c).length === totalChunks) {
            this.handleFullMessageFromMemory(address, chunkData.chunks, rinfo, sessionId);
        }
    }

    async handleFullMessageFromMemory(address, chunks, rinfo, sessionId) {
        const fullMessage = Buffer.concat(chunks).toString();
        console.log(`Full message received from ${address}: ${fullMessage}`);

        try {
            const request = JSON.parse(fullMessage);
            console.log('Parsed full message request:', request);

            if (this.requestHandler) {
                const response = await this.requestHandler(request, sessionId);
                console.log('Generated response for full message:', response);

                const encryptedResponse = this.encryptMessage(JSON.stringify(response));
                this.udpResponseSocket.send(encryptedResponse, rinfo.port, rinfo.address, (err) => {
                    if (err) console.error('Error sending response:', err);
                    else console.log('Response sent successfully for full message');
                });
            } else {
                console.log('No request handler set for full message');
            }
        } catch (error) {
            console.error('Error handling full message:', error);
        }

        this.chunkStore.delete(address);
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

        const privateKey = forge.pki.privateKeyFromPem(this.dataprivateKey);
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

    getSession(sessionId) {
        return this.sessions.get(sessionId);
    }

    updateSession(sessionId, newData) {
        if (this.sessions.has(sessionId)) {
            const session = this.sessions.get(sessionId);
            Object.assign(session, newData);
            this.sessions.set(sessionId, session);
            return true;
        }
        return false;
    }

    deleteSession(sessionId) {
        return this.sessions.delete(sessionId);
    }

    listSessions() {
        return Array.from(this.sessions.keys());
    }
}

module.exports = HttpServer;
