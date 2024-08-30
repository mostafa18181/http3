/**
 * This file defines an HttpServer class that implements an HTTP/3 server using UDP in Node.js.
 * The server handles client connections, manages sessions, and processes incoming requests with
 * secure encrypted communication. Here’s a breakdown of the key functionalities provided by the server:
 *
 * Initialization and Configuration:
 *
 * - The server is initialized with an IP address, port, public key, and private key paths for TLS encryption.
 * - It sets up a UDP server to listen for incoming connections and manages communication securely.
 *
 * Session Management:
 *
 * - The server manages sessions using unique session IDs, which are generated during the handshake process.
 * - Sessions are stored in memory with a timeout mechanism to clean up inactive sessions.
 *
 * Handling Requests:
 *
 * - The server listens for incoming UDP messages and processes them based on the session ID and request data.
 * - It decrypts messages, handles replay attacks using nonces, and processes requests according to the specified method (e.g., GET, POST).
 * - If data is too large, it is handled in chunks to manage memory efficiently.
 *
 * Security and Encryption:
 *
 * - All messages are encrypted with AES-256-GCM for confidentiality and integrity.
 * - The server uses RSA encryption to securely exchange keys between the client and server.
 *
 * Handling Full Messages and Responses:
 *
 * - The server handles full messages reconstructed from chunks and sends back encrypted responses.
 * - It ensures that the responses are securely transmitted back to the client using encrypted channels.
 *
 * Request Queue and Rate Limiting:
 *
 * - The server limits the number of concurrent requests and queues excess requests to manage server load.
 *
 * Error Handling:
 *
 * - The server includes error handling for various stages of message processing, including decryption and request parsing errors.
 */

const dgram = require('dgram');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const os = require('os');
const forge = require('node-forge');

const SESSION_TIMEOUT = 300000; // 5 minutes

class HttpServer {
    // Constructor initializes server with address, port, and paths to public/private keys for encryption
    constructor(address, port, publicKeyPath, privateKeyPath) {
        this.dataPublicKey = fs.readFileSync(publicKeyPath, 'utf8');
        this.dataprivateKey = fs.readFileSync(privateKeyPath, 'utf8');
        this.sessions = new Map();
        this.nonceSet = new Set();
        this.nonceTTL = 60000;
        this.maxConcurrentRequests = 10;
        this.requestQueue = [];
        this.activeRequests = 0;
        this.maxWindowSize = 1024 * 1024; // Maximum data window size to handle
        this.currentWindowSize = 0;
        this.address = address || 'localhost';
        this.udpPort = port || 4434;
        this.chunkStore = new Map(); // Stores message chunks to handle large data
        this.tempDir = path.join(os.tmpdir(), 'http3server');
        fs.mkdirSync(this.tempDir, {recursive: true});
        this.udpResponseSocket = dgram.createSocket('udp4');
        this.routes = [];
        this.setupUDPServer(); // Sets up the UDP server
    }

    // Set up UDP server to handle incoming messages and connections
    setupUDPServer() {
        this.udpServer = dgram.createSocket('udp4');
        console.log("UDP server setup started");

        // Handles incoming UDP messages
        this.udpServer.on('message', async (msg, rinfo) => {
            console.log(`UDP server received: ${msg} from ${rinfo.address}:${rinfo.port}`);

            const decryptedMsg = this.decryptMessage(msg.toString()); // Decrypt the incoming message

            if (!decryptedMsg) {
                console.log('Decrypted message is invalid, dropping packet');
                return;
            }

            const {nonce, sessionId, data, chunkNumber, chunk, totalChunks} = this.parseMessage(decryptedMsg);

            // Check for replay attacks using nonces
            if (this.isReplayAttack(nonce)) {
                console.log('Replay attack detected');
                return;
            }

            this.addNonce(nonce);
            if (data && data.startsWith('HELLO')) {
                this.handleInitialHandshake(rinfo, data); // Handle initial connection handshake
            } else {
                if (!this.sessions.has(sessionId)) {
                    console.log('Invalid session ID, dropping packet');
                    return;
                }

                // Check if the current window size is exceeded
                if (this.currentWindowSize + (chunk ? chunk.length : (data ? data.length : 0)) > this.maxWindowSize) {
                    console.log('Window size exceeded, dropping data');
                    return;
                }
                this.currentWindowSize += (chunk ? chunk.length : (data ? data.length : 0));

                // Store chunks in memory if data is received in parts
                if (chunk !== undefined && chunkNumber !== undefined && totalChunks !== undefined) {
                    this.storeChunkInMemory(chunkNumber, chunk, totalChunks, rinfo, sessionId);
                } else {
                    if (data) {
                        await this.handleRequest(rinfo, data, sessionId); // Handle complete request data
                    } else {
                        console.log('Received undefined data, dropping packet');
                    }
                }
            }
        });

        // Error handling for UDP server errors
        this.udpServer.on('error', (err) => {
            console.log(`UDP server error: ${err.stack}`);
            this.udpServer.close();
        });

        // Bind server to specified address and port
        this.udpServer.bind(this.udpPort, this.address, () => {
            console.log(`UDP server listening on ${this.address}:${this.udpPort}`);
        });
    }

    // Set a custom request handler for processing incoming requests
    setRequestHandler(handler) {
        this.requestHandler = handler;
    }

    // Handle incoming requests with session management and request parsing
    async handleRequest(rinfo, data, sessionId) {
        if (this.activeRequests >= this.maxConcurrentRequests) {
            this.requestQueue.push({rinfo, data, sessionId});
            console.log('Request added to queue');
            return;
        }

        this.activeRequests++;
        try {
            const request = JSON.parse(data); // Parse incoming request data
            console.log('Parsed request:', request);

            // Call the request handler to process the request
            if (this.requestHandler) {
                const response = await this.requestHandler(request, sessionId);
                console.log('Generated response:', response);

                const encryptedResponse = this.encryptMessage(JSON.stringify(response)); // Encrypt the response
                // Send the encrypted response back to the client
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

    // Parse incoming message to extract relevant fields
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

    // Check if a nonce has already been used to detect replay attacks
    isReplayAttack(nonce) {
        return this.nonceSet.has(nonce);
    }

    // Add a nonce to the set to track it for a limited time
    addNonce(nonce) {
        this.nonceSet.add(nonce);
        setTimeout(() => {
            this.nonceSet.delete(nonce);
        }, this.nonceTTL);
    }

    // Handle the initial handshake to establish a session
    handleInitialHandshake(rinfo, data) {
        console.log('Handling initial handshake');

        const sessionId = crypto.randomBytes(16).toString('hex'); // Generate a unique session ID
        this.sessions.set(sessionId, {publicKey: this.dataPublicKey, privateKey: this.dataprivateKey});

        // Set a timeout to clean up the session after inactivity
        setTimeout(() => {
            this.sessions.delete(sessionId);
        }, SESSION_TIMEOUT);

        const response = JSON.stringify({type: 'handshake', publicKey: this.dataPublicKey, sessionId});
        const encryptedResponse = this.encryptMessage(response);

        // Send the handshake response back to the client
        this.udpResponseSocket.send(encryptedResponse, rinfo.port, rinfo.address, (err) => {
            if (err) console.error(err);
        });

        console.log('Sent public key for handshake');
    }

    // Store message chunks in memory until a full message is reconstructed
    storeChunkInMemory(chunkNumber, chunk, totalChunks, rinfo, sessionId) {
        const address = rinfo.address + ':' + rinfo.port;
        if (!this.chunkStore.has(address)) {
            this.chunkStore.set(address, {totalChunks, chunks: [], sessionId});
        }

        const chunkData = this.chunkStore.get(address);
        chunkData.chunks[chunkNumber] = chunk;
        console.log(`Stored chunk ${chunkNumber} for ${address}`);

        // Check if all chunks have been received and handle the full message
        if (chunkData.chunks.filter(c => c).length === totalChunks) {
            this.handleFullMessageFromMemory(address, chunkData.chunks, rinfo, sessionId);
        }
    }

    // Handle full message once all chunks have been received
    async handleFullMessageFromMemory(address, chunks, rinfo, sessionId) {
        const fullMessage = Buffer.concat(chunks).toString();
        console.log(`Full message received from ${address}: ${fullMessage}`);

        try {
            const request = JSON.parse(fullMessage); // Parse the full message
            console.log('Parsed full message request:', request);

            // Process the request with the custom handler
            if (this.requestHandler) {
                const response = await this.requestHandler(request, sessionId);
                console.log('Generated response for full message:', response);

                const encryptedResponse = this.encryptMessage(JSON.stringify(response));
                // Send the response back to the client
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

        // Clean up stored chunks after processing
        this.chunkStore.delete(address);
    }

    // Encrypt message using AES and RSA for secure communication
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

    // Decrypt incoming encrypted message
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

    // Get session data for a specific session ID
    getSession(sessionId) {
        return this.sessions.get(sessionId);
    }

    // Update session data with new information
    updateSession(sessionId, newData) {
        if (this.sessions.has(sessionId)) {
            const session = this.sessions.get(sessionId);
            Object.assign(session, newData);
            this.sessions.set(sessionId, session);
            return true;
        }
        return false;
    }

    // Delete a session from the session list
    deleteSession(sessionId) {
        return this.sessions.delete(sessionId);
    }

    // List all active session IDs
    listSessions() {
        return Array.from(this.sessions.keys());
    }
}

module.exports = HttpServer;
