/**
 * This file defines an HttpClient class that implements a client for HTTP/3 over UDP using Node.js.
 * The client handles secure communication with a server, manages sessions, and allows sending of HTTP
 * requests using encryption. Here’s a breakdown of the key functionalities provided by the client:
 *
 * Initialization and Configuration:
 *
 * - The client is initialized with an IP address, port, and paths to public and private keys for TLS encryption.
 * - It sets up a UDP client to communicate with the server securely.
 *
 * Session Initialization:
 *
 * - The client starts a session by sending an initial handshake message to the server, encrypted with RSA and AES.
 * - It waits for the server to respond with a session ID, which is used for all subsequent communications.
 *
 * Sending HTTP Requests:
 *
 * - The client sends HTTP requests (e.g., GET, POST) to the server using the established session.
 * - Requests are split into chunks if necessary to handle large data efficiently.
 *
 * Encryption and Decryption:
 *
 * - Messages are encrypted with AES-256-GCM for confidentiality and integrity.
 * - RSA encryption is used to securely exchange keys between the client and server.
 *
 * Chunked Messaging:
 *
 * - Large messages are divided into smaller chunks before being sent to manage transmission and ensure reliable delivery.
 */

const dgram = require('dgram'); // Import dgram for UDP socket communication
const crypto = require('crypto'); // Import crypto for encryption and decryption
const forge = require('node-forge'); // Import node-forge for key management and encryption
const fs = require('fs'); // Import fs to handle file system operations

class HttpClient {
    // Constructor initializes the client with server address, port, and paths to public/private keys
    constructor(address, port, publicKeyPath, privateKeyPath) {
        this.dataPublicKey = fs.readFileSync(publicKeyPath, 'utf8'); // Load the public key
        this.dataPrivateKey = fs.readFileSync(privateKeyPath, 'utf8'); // Load the private key
        this.address = address || 'localhost'; // Set default address to localhost
        this.udpPort = port || 4434; // Set default UDP port
        this.sessionId = null; // Session ID to track the active session
        this.udpClient = dgram.createSocket('udp4'); // Create a UDP socket
    }

    // Initialize a new session by sending a handshake message to the server
    initializeSession() {
        return new Promise((resolve, reject) => {
            const nonce = crypto.randomBytes(16).toString('hex'); // Generate a random nonce
            const message = JSON.stringify({nonce, sessionId: null, data: 'HELLO'}); // Create the handshake message
            const encryptedMessage = this.encryptMessage(message); // Encrypt the message

            // Send the encrypted handshake message to the server
            this.udpClient.send(encryptedMessage, this.udpPort, this.address, (err) => {
                if (err) {
                    console.error('Error sending initial handshake:', err);
                    reject(err);
                } else {
                    console.log('Initial handshake message sent');
                }
            });

            // Listen for responses from the server
            this.udpClient.on('message', (msg, rinfo) => {
                const decryptedMsg = this.decryptMessage(msg.toString()); // Decrypt the received message
                console.log(`Received response from ${rinfo.address}:${rinfo.port}: ${decryptedMsg}`);

                try {
                    const response = JSON.parse(decryptedMsg); // Parse the response
                    if (response.type === 'handshake') {
                        this.sessionId = response.sessionId; // Store the session ID
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

    // Send an HTTP request to the server with the specified method, path, headers, and body
    async sendHttpRequest(method, path, headers, body) {
        if (!this.sessionId) {
            console.error('No session ID. Initialize session first.');
            return;
        }

        // Create the request object to send
        const request = JSON.stringify({
            sessionId: this.sessionId,
            method,
            path,
            headers,
            body
        });

        console.log('Sending HTTP request:', request);

        // Send the request in chunks to manage large data
        await this.sendChunkedMessage(request, 1024);
    }

    // Send the message in chunks of the specified size
    async sendChunkedMessage(message, chunkSize) {
        let offset = 0;
        let chunkNumber = 0;
        const udpClient = this.udpClient;

        // Function to send a single chunk of the message
        const sendChunk = (chunkNumber, chunk) => {
            return new Promise((resolve, reject) => {
                const packet = JSON.stringify({
                    sessionId: this.sessionId,
                    chunkNumber,
                    chunk,
                    totalChunks: Math.ceil(message.length / chunkSize)
                });
                const encryptedPacket = this.encryptMessage(packet); // Encrypt the chunk

                // Send the encrypted chunk to the server
                udpClient.send(encryptedPacket, this.udpPort, this.address, (err) => {
                    if (err) {
                        console.error(err);
                        reject(err);
                    } else {
                        resolve();
                    }
                });
            });
        };

        const promises = [];

        // Split the message into chunks and send each chunk
        while (offset < message.length) {
            const chunk = message.slice(offset, offset + chunkSize);
            promises.push(sendChunk(chunkNumber, chunk));
            offset += chunkSize;
            chunkNumber++;
        }

        await Promise.all(promises); // Wait for all chunks to be sent
    }

    // Encrypt a message using AES and RSA for secure transmission
    encryptMessage(message) {
        const aesKey = crypto.randomBytes(32); // Generate a random AES key
        const iv = crypto.randomBytes(16); // Generate a random initialization vector

        // Encrypt the message using AES-256-GCM
        const cipher = crypto.createCipheriv('aes-256-gcm', aesKey, iv);
        let encrypted = cipher.update(message, 'utf8', 'hex');
        encrypted += cipher.final('hex');
        const authTag = cipher.getAuthTag().toString('hex');
        const encryptedMessage = iv.toString('hex') + ':' + encrypted + ':' + authTag;

        // Encrypt the AES key using the server's public key with RSA
        const publicKey = forge.pki.publicKeyFromPem(this.dataPublicKey);
        const encryptedKey = publicKey.encrypt(aesKey.toString('hex'), 'RSA-OAEP', {
            md: forge.md.sha256.create(),
            mgf1: forge.mgf.mgf1.create(forge.md.sha1.create())
        });

        return forge.util.encode64(encryptedKey) + ':' + encryptedMessage; // Return the encrypted key and message
    }

    // Decrypt a received message using the client's private key and AES
    decryptMessage(encryptedData) {
        const parts = encryptedData.split(':');
        const [encryptedKeyBase64, iv, encrypted, authTag] = parts;

        if (parts.length !== 4) {
            console.error('Invalid encrypted data format');
            return '';
        }

        // Decrypt the AES key using the client's private key
        const privateKey = forge.pki.privateKeyFromPem(this.dataPrivateKey);
        const encryptedKey = forge.util.decode64(encryptedKeyBase64);
        const aesKeyHex = privateKey.decrypt(encryptedKey, 'RSA-OAEP', {
            md: forge.md.sha256.create(),
            mgf1: forge.mgf.mgf1.create(forge.md.sha1.create())
        });
        const aesKey = Buffer.from(aesKeyHex, 'hex');

        // Decrypt the message using AES-256-GCM
        const decipher = crypto.createDecipheriv('aes-256-gcm', aesKey, Buffer.from(iv, 'hex'));
        decipher.setAuthTag(Buffer.from(authTag, 'hex'));
        let decrypted = decipher.update(encrypted, 'hex', 'utf8');
        decrypted += decipher.final('utf8');
        return decrypted;
    }
}

module.exports = HttpClient; // Export the HttpClient class for external use
