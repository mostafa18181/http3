 
/**
 * HttpClient Class
 * 
 * This class implements an HTTP/3 client over UDP. It is designed to communicate 
 * securely with an HTTP/3 server, leveraging advanced features like encryption, 
 * QPACK header compression, and chunked data transfer.
 * 
 * Features:
 * - **Session Management**: Manages sessions with a unique `sessionId` and `connectionId`.
 * - **Secure Communication**: Encrypts data using AES-256-GCM and secures the key with RSA-OAEP.
 * - **QPACK Compression**: Compresses and decompresses headers for efficient HTTP/3 communication.
 * - **Chunked Data Transfer**: Splits large messages into smaller chunks for UDP transmission.
 * - **Flow Control**: Manages congestion and retransmission using sliding window and timeouts.
 * - **Dynamic Tables**: Supports dynamic header compression tables for efficient header storage.
 * - **ACK Handling**: Manages acknowledgment of received chunks and schedules retransmission if needed.
 * 
 * Usage:
 * - Establish a session using `initializeSession()`.
 * - Send HTTP requests using `sendHttpRequest(method, path, headers, body)`.
 * - Automatically handles chunking, encryption, and retransmissions.
 * 
 * Dependencies:
 * - Node.js `dgram` for UDP socket communication.
 * - `crypto` and `node-forge` for encryption and decryption.
 * - DynamicTable and QPACK modules for header compression.
 * 
 * Example:
 * ```
 * const HttpClient = require('./HttpClient');
 * const client = new HttpClient('localhost', 4434, './serverPublicKey.pem', './clientPrivateKey.pem');
 * 
 * (async () => {
 *     await client.initializeSession();
 *     await client.sendHttpRequest('GET', '/example', { 'Content-Type': 'application/json' }, null);
 * })();
 */

const dgram = require('dgram'); // Import dgram for UDP socket communication
const crypto = require('crypto'); // Import crypto for encryption and decryption
const forge = require('node-forge'); // Import node-forge for key management and encryption
const fs = require('fs'); // Import fs to handle file system operations
 const  DynamicTable = require('./DynamicTable');
const QPACK = require('./QPACK');
const staticTable = require('./StaticTable');
const MAX_RETRIES = 5; // Maximum number of retries for retransmission

class HttpClient {
    // Constructor initializes the client with server address, port, and paths to public/private keys
    constructor(address, port, publicKeyPath, privateKeyPath) {
        this.dataPublicKey = fs.readFileSync(publicKeyPath, 'utf8'); // Load the public key
        this.dataPrivateKey = fs.readFileSync(privateKeyPath, 'utf8'); // Load the private key
        this.address = address || 'localhost'; // Set default address to localhost
        this.udpPort = port || 4434; // Set default UDP port
        this.sessionId = null; // Session ID to track the active session
        this.udpClient = dgram.createSocket('udp4'); // Create a UDP socket
        this.streams = new Map(); // Manage active streams
        this.streamCounter = 1; // Stream ID counter
        // Define window size and counters
        this.windowSize = 64 * 1024; // 64 KB default window size
        this.bytesInFlight = 0; // Bytes sent but not yet acknowledged
        this.maxWindowSize = 256 * 1024; // Maximum window size (256 KB)
        this.congestionWindow = 64 * 1024; // 64 KB
        this.ssthresh = 32 * 1024; // Slow Start Threshold
        this.bytesInFlight = 0; // Bytes sent but not yet acknowledged
         this.headerTable = [];  // Client's header table
        this.dynamicTable = new DynamicTable(4096); // Maximum dynamic table size
        this.qpack = new QPACK(this.dynamicTable);  // QPACK for header compression
        this.pendingChunks = new Map();  // Initialize pending chunks

    }
 
    // Initialize a new session by sending a handshake message to the server
    initializeSession() {
        return new Promise((resolve, reject) => {
            const nonce = crypto.randomBytes(16).toString('hex'); // Generate a random nonce
            const message = JSON.stringify({       frameType: 'HANDSHAKE',nonce, sessionId: null, data: 'HELLO'}); // Create the handshake message
            const encryptedMessage = this.encryptMessage(message); // Encrypt the message
    
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
                const decryptedMsg = this.decryptMessage(msg.toString());
                console.log(`Received message from ${rinfo.address}:${rinfo.port}: ${decryptedMsg}`);
            
                try {
                    const response = JSON.parse(decryptedMsg); // Parse the message
 
                    
                    let { frameType } = response; // Extract the frameType
                    if(rinfo.address>0){
                        frameType="SUCCESS";
                    }
                    if (response.frameType === 'HANDSHAKE') {
                         // Handle handshake
                        this.sessionId = response.sessionId; // Store the session ID
                        this.connectionId = response.connectionId; // Store the Connection ID
                        console.log(`Session ID and Connection ID received: ${this.sessionId}, ${this.connectionId}`);
                        resolve();// Handshake completed
                    } else if (frameType === 'SETTINGS') {
                        // Handle SETTINGS message
                        this.handleSettingsFrame(data.settings); // Update settings
                    } 
                    else if (frameType !== 'SUCCESS'&&response.success!=true)
                          {
 
                        console.error(`Unknown message type received: ${response.frameType}`);
                    }
                } catch (error) {
                    console.error('Failed to parse message:', error);
                }
            });
            
        });
    }
    
    async sendHttpRequest(method, path, headers, body) {
    
        if (!this.sessionId) {
            console.error('No session ID. Initialize session first.');
            return;
        }
    
        // Compress headers before sending
        const compressedHeaders = this.compressHeaders(headers);
    
        const streamId = this.streamCounter++;
        this.streams.set(streamId, { method, path, headers: compressedHeaders, body });
    
        // Add frameType to the message
        const headerFrame = {
            frameType: 'HEADERS', // Add frame type
            sessionId: this.sessionId,
            streamId,
            headers: compressedHeaders, // Send compressed headers
            path,
            method,
            body: null,  // Body is not sent initially
        };
    
        console.log(`Sending HEADERS frame:`, headerFrame);

        // Send headers in chunks
        try {
            await this.sendChunkedMessage(JSON.stringify(headerFrame), 1024, streamId, "HEADERS");
        } catch (error) {
            console.error(`Error sending headers for stream ${streamId}:`, error);
            return;
        }
    
        // Send message body in chunks
        if (body) {
            try {
                const bodyFrame = {
                    frameType: 'DATA',
                    sessionId: this.sessionId,
                    streamId,
                    path,
                    chunk: body,
                };

                await this.sendChunkedMessage(JSON.stringify(bodyFrame), 1024, streamId, "DATA",path);
            
            } catch (error) {
                console.error(`Error sending body for stream ${streamId}:`, error);
                return;
            }
        }
    
        console.log(`Request for stream ${streamId} sent successfully.`);
    }
    
    
    async sendChunkedMessage(message, chunkSize, streamId, frameType = "DATA",path) {
    
        let offset = 0;
        let chunkNumber = 0;
        const udpClient = this.udpClient;
        const TIMEOUT = 5000; // 5 seconds timeout for ACK
        const MAX_RETRIES = 5; // Maximum number of retransmissions
        this.awaitingAcks = new Map(); // Store timers for retransmissions
        this.retransmissionCount = new Map(); // Track retransmissions for each chunk
        const sendChunk = (chunkNumber, chunk) => {
            return new Promise((resolve, reject) => {
                // Check for congestion window limit
                if (this.bytesInFlight + chunk.length > this.congestionWindow) {
                    console.log("Congestion window is full, waiting...");
                    const interval = setInterval(() => {
                        if (this.bytesInFlight + chunk.length <= this.congestionWindow) {
                            clearInterval(interval);
                            resolve(); // Allow sending
                        }
                    }, 50); // Check every 50ms
                    return;
                }
        
                // Packet structure
                const packet = JSON.stringify({
                    connectionId: this.connectionId,
                    frameType,
                    sessionId: this.sessionId,
                    streamId,
                    chunkNumber,
                    totalChunks: Math.ceil(message.length / chunkSize),
                    chunk,
                    path,
                    type: "DATA"
                });
                console.log(`Chunk ${chunkNumber} with path: ${path}`);

                const encryptedPacket = this.encryptMessage(packet);
                console.log(`Encrypted packet for chunk ${chunkNumber}:`, packet);

                // Track retransmission count
                const retries = this.retransmissionCount.get(chunkNumber) || 0;
                if (retries >= MAX_RETRIES) {
                    console.error(`Max retransmissions reached for chunk ${chunkNumber}. Closing connection.`);
                    this.closeConnection();
                    reject(new Error(`Max retransmissions reached for chunk ${chunkNumber}`));
                    return;
                }
        
                // Sending the packet
                udpClient.send(encryptedPacket, this.udpPort, this.address, (err) => {
                    if (err) {
                        console.error(`Error sending chunk ${chunkNumber}:`, err);
                        this.retransmissionCount.set(chunkNumber, retries + 1); // Increment retry count
                        this.scheduleRetransmission(chunkNumber, chunk); // Schedule retransmission
                        reject(err);
                    } else {
                        console.log(`Sent chunk ${chunkNumber}`);
                        this.bytesInFlight += chunk.length; // Increment bytes in flight
                        this.pendingChunks.set(chunkNumber, {
                            chunk,
                            timeout: setTimeout(() => {
                                console.log(`Timeout for chunk ${chunkNumber}, scheduling retransmission.`);
                                this.scheduleRetransmission(chunkNumber, chunk,path);
                            }, TIMEOUT),  
                        });
                        resolve();
                    }
                });
            });
        };
        
       
    
        const promises = [];
 
        const messageData = JSON.stringify(message)

        while (offset < messageData.length) {
            const chunk = messageData.slice(offset, offset + chunkSize);

     

            promises.push(sendChunk(chunkNumber, chunk));
            offset += chunkSize;
            chunkNumber++;
        }
    
        try {
            await Promise.all(promises);
            console.log("All chunks sent successfully.");
        } catch (error) {
            console.error("Error during chunk transmission:", error.message);
        }
    
        console.log("Waiting for all ACKs...");
        while (this.awaitingAcks.size > 0) {
            await new Promise((resolve) => setTimeout(resolve, 500));
        }
    }
    
    sendChunk(chunkNumber, chunk, path) {
        return new Promise((resolve, reject) => {
            const packet = JSON.stringify({
                connectionId: this.connectionId,
                frameType: "DATA",
                sessionId: this.sessionId,
                streamId: this.streamId,
                chunkNumber,
                totalChunks: this.totalChunks,
                chunk,
                 path,
                type: "DATA",
            });

            const encryptedPacket = this.encryptMessage(packet);
            this.udpClient.send(encryptedPacket, this.udpPort, this.address, (err) => {
                if (err) {
                    reject(err);
                } else {
                    resolve();
                }
            });
        });
    }
    

    scheduleRetransmission(chunkNumber, chunk, path) {
        if (!this.udpClient) {
            console.error(`UDP client is not active. Cannot retransmit chunk ${chunkNumber}.`);
            return;
        }
        const retries = this.retransmissionCount.get(chunkNumber) || 0;
        if (retries < MAX_RETRIES) {
            console.log(`Retransmitting chunk ${chunkNumber}, attempt ${retries + 1}`);
            this.retransmissionCount.set(chunkNumber, retries + 1);
            this.sendChunk(chunkNumber, chunk, path).catch((err) => {
                console.error(`Failed to retransmit chunk ${chunkNumber}:`, err);
            });
        } else {
            console.error(`Max retries reached for chunk ${chunkNumber}. Giving up.`);
            this.closeConnection();
        }
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
        try { const parts = encryptedData.split(':');
        const [encryptedKeyBase64, iv, encrypted, authTag] = parts;

        if (parts.length !== 4) {
            throw new Error('Invalid encrypted data format');
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
    } catch (error) {
        console.error("Decryption error:", error);
        return null; // Return null instead of sending an error message
    }
    }

    handleResponse(msg) {
        const decryptedMsg = this.decryptMessage(msg.toString());
        const { streamId, type, data, headers } = JSON.parse(decryptedMsg);
    
        if (this.streams.has(streamId)) {
            // Decompress the response headers
            const responseHeaders = this.decompressHeaders(headers);
    
            console.log(`Response for stream ${streamId}:`, data);
            this.streams.delete(streamId);// Mark the stream as completed
        } else {
            console.error(`Unknown stream ID: ${streamId}`);
        }
    }
    handleAck(streamId, chunkNumber) {
        if (this.awaitingAcks.has(chunkNumber)) {
            // Clear the timer for this chunk
            clearTimeout(this.awaitingAcks.get(chunkNumber));
            this.awaitingAcks.delete(chunkNumber);
    
            // Retrieve the chunk size before deleting it
            const chunkSize = this.pendingChunks.get(chunkNumber)?.length || 0;
    
            // Remove chunk metadata
            if (this.pendingChunks.has(chunkNumber)) {
                this.pendingChunks.delete(chunkNumber); 
            } else {
                console.warn(`Attempting to delete non-existent chunk metadata for chunk ${chunkNumber}`);
            }
    
            // Update bytes in flight
            this.bytesInFlight -= chunkSize; 
    
            console.log(`ACK received for chunk ${chunkNumber} of stream ${streamId}`);
        } else {
            console.warn(`ACK received for unknown or already acknowledged chunk ${chunkNumber}`);
            return;
        }
    }
    
    
 
    isSocketActive() {
        return this.udpClient !== null && this.udpClient.connected;
    }
    
    closeConnection() {
        if (this.udpClient) {
            console.log("Closing UDP client...");
            this.udpClient.close();
            this.udpClient = null; // Prevent multiple closures
        }
        this.pendingChunks.clear();
        this.retransmissionCount.clear();
    }
    
    
   
    
    compressHeaders(headers) {
         
        return this.qpack.compressHeaders(headers);

    }
    
    decompressHeaders(compressedHeaders) {
     
        return this.qpack.decompressHeaders(compressedHeaders);

    }
    async handleSettingsFrame(settings) {
        if (settings.maxTableSize) {
            this.dynamicTable.maxSize = settings.maxTableSize; // Update the size of the dynamic table
            console.log(`Dynamic table size updated to: ${settings.maxTableSize}`);
        }
    }
    
    handleTimeoutOrLoss() {
        this.ssthresh = Math.max(this.congestionWindow / 2, 1024); // Update threshold
        this.congestionWindow = 1024; // Reset to minimum window size
        this.retransmissionCount = (this.retransmissionCount || 0) + 1;// Increment timeout count
        if (this.retransmissionCount > MAX_RETRIES) {
            console.error('Max retransmission attempts reached. Closing connection.');
            this.closeConnection();
            return; // Stop further operations after closing the connection
        }
        console.log(`Timeout occurred. Reducing congestion window to ${this.congestionWindow} bytes. Retransmissions: ${this.retransmissionCount}`);
    }
    
    // Method to send an error message
    sendError(rinfo, errorCode, message) {
        const errorPacket = JSON.stringify({
            frameType: "ERROR",
            errorCode,
            message
        });
        const encryptedError = this.encryptMessage(errorPacket);
    
        // Check if rinfo exists
        if (rinfo) {
            this.udpServer.send(encryptedError, rinfo.port, rinfo.address, (err) => {
                if (err) console.error(`Error sending error packet: ${err}`);
            });
        } else {
            console.error(`Error: ${message} (Error Code: ${errorCode})`);
        }
    }


}

module.exports = HttpClient; // Export the HttpClient class for external use
