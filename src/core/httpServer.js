 /**
 * HttpServer Class
 * 
 * This class provides an implementation of an HTTP/3 server over UDP.
 * It incorporates features like secure communication using AES and RSA encryption,
 * QPACK compression for headers, session management, and flow control.
 * 
 * Features:
 * - **Session Management**: Handles sessions with `sessionId` and `connectionId`.
 * - **Secure Communication**: Encrypts data using AES-256-GCM and secures the key using RSA-OAEP.
 * - **QPACK Compression**: Compresses and decompresses headers for efficient data transfer.
 * - **Chunked Data Transmission**: Supports handling large data by dividing it into smaller chunks.
 * - **Flow Control**: Implements congestion control mechanisms with window size adjustments.
 * - **Error Handling**: Provides mechanisms to handle invalid data, lost packets, and timeouts.
 * - **Dynamic Tables**: Manages dynamic header tables to store compressed headers efficiently.
 * 
 * Usage:
 * - The server can handle requests from multiple clients simultaneously.
 * - It supports frame types like `HANDSHAKE`, `HEADERS`, `DATA`, `PING`, and `CLOSE`.
 * - Chunked data is stored temporarily and reconstructed upon receipt of all chunks.
 * 
 * Dependencies:
 * - Node.js `dgram` module for UDP communication.
 * - `crypto` and `node-forge` for encryption and decryption.
 * - DynamicTable and QPACK modules for header compression and dynamic table management.
 * 
 * Example:
 * ```
 * const HttpServer = require('./HttpServer');
 * const server = new HttpServer('localhost', 4434, './publicKey.pem', './privateKey.pem');
 * 
 * server.setRequestHandler(async (request, body, sessionId, path) => {
 *     console.log('Request received:', request);
 *     return { headers: { status: 200 }, body: 'Hello, World!' };
 * });
 * 
 * console.log('HTTP/3 server is running...');
 */

const dgram = require('dgram');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const os = require('os');
const forge = require('node-forge');
const DynamicTable = require('./DynamicTable');
const QPACK = require('./QPACK');
const staticTable = require('./StaticTable');
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
        // Define window size and counters
        this.windowSize = 64 * 1024; // 64 KB default window size
        this.bytesInFlight = 0; // Bytes sent but not yet acknowledged
        this.maxWindowSize = 256 * 1024; // Maximum window size (256 KB)
        this.dynamicTable = new DynamicTable(4096); // Maximum size of the dynamic table
        this.qpack = new QPACK(this.dynamicTable);  // QPACK for header compression and decompression
        this.setupUDPServer(); // Sets up the UDP server
        this.streams = new Map();// Managing active streams
        this.congestionWindow = 64 * 1024; // 64 KB
        this.ssthresh = 32 * 1024; // Slow Start Threshold
        this.bytesInFlight = 0; // Bytes sent but not yet acknowledged
        this.receivedChunks = new Map(); // Key: chunk number, Value: chunk data

        this.headerTable = []; // Server header table

    }

    // Set up UDP server to handle incoming messages and connections
    setupUDPServer() {
        this.udpServer = dgram.createSocket('udp4');
        console.log("UDP server setup started");
    
        this.udpServer.on("message", async (msg, rinfo) => {
            try {

 
            const decryptedMsg = this.decryptMessage(msg.toString());
 
            if (!decryptedMsg) {
            //    console.log("Decrypted message is invalid, dropping packet");
                return;
            }
            //   try {

             const { frameType, streamId, sessionId, connectionId, chunkNumber, chunk, totalChunks } = JSON.parse(decryptedMsg);
           
            
 
 
           
            if (frameType === "HANDSHAKE") {
                // Call the method to handle handshake
                this.handleInitialHandshake(rinfo, decryptedMsg);
                return; // Prevent further processing after handshake
            }

            
            if (frameType !== "HEADERS" && frameType !== "DATA") {
                this.sendError(rinfo, "FRAME_ENCODING_ERROR", "Unknown frame type.");
                return;
            }
             const session = this.sessions.get(sessionId);
        
 
            if (!session || session.connectionId !== connectionId) {
                console.error(`Invalid or expired session ID: ${sessionId}`);
                this.sendError(rinfo, "INTERNAL_ERROR", `Invalid or expired session ID: ${sessionId}`);
                return;
            }
            // Check Connection ID
            if (session.connectionId !== connectionId) {
                console.error(`Invalid Connection ID for session ${sessionId}`);
                return;
            }
    
            // Update address and port
            session.address = rinfo.address;
            session.port = rinfo.port;
    
            // Process frame
            switch (frameType) {
                case "HEADERS":
                    console.log(`Received HEADERS frame for stream ${streamId}`);
                    try {
         
                        
                        if (!chunk) {
                            console.error('Chunk is missing or invalid');
                            return;
                        }
                        const parsedChunk = JSON.parse(chunk);  
                        const chunkData = typeof parsedChunk === 'string' ? JSON.parse(parsedChunk) : parsedChunk; // تجزیه اضافی اگر لازم باشد
 

                         

                        const headers = chunkData.headers;

                      

                       
                                if (
                                    !headers ||
                                    !Array.isArray(headers) ||
                                    !headers.every(h =>
                                        (h.type === 'literal' && h.header && h.header.key && h.header.value) || 
                                        (h.type === 'indexed' && typeof h.index === 'number' && h.table)
                                    )
                                )  {
                           
           
                                      console.error(`Invalid headers format for stream ${streamId}`);
                                      this.sendError(rinfo, "HEADER_VALIDATION_ERROR", "Headers format is invalid.");
                                      break;
                                  }
                              
            
                        const decompressedHeaders = this.decompressHeaders(headers);
             
                        const stream = this.streams.get(streamId) || {};
                        stream.headers = decompressedHeaders; 
                        this.streams.set(streamId, stream);
            
                     } catch (err) {
                        console.error(`Error processing HEADERS frame for stream ${streamId}:`, err);
                        this.sendError(rinfo, "HEADER_PROCESSING_ERROR", "Error processing headers.");
                    }
                    break;
                case "DATA":
                    this.storeChunkInMemory(chunkNumber, chunk, totalChunks, rinfo, sessionId);
                    break;
    
                case "SETTINGS":
                    console.log("Received SETTINGS frame");
                    this.handleSettingsFrame(data.settings);

                    break;
    
                case "PING":
                    console.log("Received PING frame");
                    this.sendAck(rinfo, streamId, chunkNumber, "PONG");
                    break;
    
                case "CLOSE":
                    console.log(`Received CLOSE frame for stream ${streamId}`);
                    this.streams.delete(streamId);
                    break;
    
                default:
                    console.error(`Unknown frame type: ${frameType}`);
            }

        } catch (error) {
                console.error("Error processing message:", error);
                this.sendError(rinfo, "INTERNAL_ERROR", "Internal server error.");
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


processNextRequest() {
    if (this.requestQueue.length === 0) {
        this.processing = false;
        return;
    }

    this.processing = true;
    const { rinfo, message, sessionId } = this.requestQueue.shift();

    this.handleRequest(rinfo, message, sessionId)
        .then(() => {
            this.processing = false;
            this.processNextRequest();
        })
        .catch((error) => {
            console.error('Error processing request:', error);
            this.processing = false;
            this.processNextRequest();
        });
}
async handleRequest(rinfo, message, sessionId) {
    // Add the request to the queue
    this.requestQueue.push({ rinfo, message, sessionId });
    console.log('Request added to queue');

    // If no processing is ongoing, process the queue
    if (!this.processing) {
        this.processNextRequest();
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
        const connectionId = crypto.randomBytes(8).toString('hex'); // Generate a unique Connection ID
    
        // Store session data, including Connection ID
        this.sessions.set(sessionId, {
            publicKey: this.dataPublicKey,
            privateKey: this.dataprivateKey,
            connectionId,
            address: rinfo.address,
            port: rinfo.port
        });
    
        // Set a timeout to clean up the session after inactivity
        setTimeout(() => {
            this.sessions.delete(sessionId);
        }, SESSION_TIMEOUT);
    
        const response = JSON.stringify({ 
            frameType: 'HANDSHAKE', 
            publicKey: this.dataPublicKey, 
            sessionId,
            connectionId  // Send Connection ID to the client
        });
        const encryptedResponse = this.encryptMessage(response);
    
        // Send the handshake response back to the client
        this.udpResponseSocket.send(encryptedResponse, rinfo.port, rinfo.address, (err) => {
            if (err) console.error(err);
        });
    
        console.log('Sent public key and Connection ID for handshake');
    }
    

  
    storeChunkInMemory(chunkNumber, chunk, totalChunks, rinfo, sessionId) {
        console.log("\nChunk:", chunk, "---", typeof chunk);
        console.log("\nChunk Number:", chunkNumber);
 
 
    const rawString = chunk.replace(/^"|"$/g, '');
 
    // Step 2: Replace \\ with nothing
    const cleanString = rawString.replace(/\\/g, '');
 
    // Step 3: Convert to JSON
    const parsedJson = JSON.parse(cleanString);

    // Step 4: Extract the path value
    const path = parsedJson.path;        
 
        const address = rinfo.address + ':' + rinfo.port;
        if (!this.chunkStore.has(address)) {
 
            this.chunkStore.set(address, { totalChunks, chunks: [], sessionId });
        }
    
        const chunkData = this.chunkStore.get(address);
        chunkData.chunks[chunkNumber] = chunk;
    
        console.log(`Stored chunk ${chunkNumber} for ${address}`);
    
        // Check if all chunks have been received
        if (chunkData.chunks.filter(c => c !== undefined).length === totalChunks) {
            console.log("All chunks received. Calling handleFullMessageFromMemory...");
 
            this.handleFullMessageFromMemory(address, chunkData.chunks,rinfo, path, sessionId);
            this.chunkStore.delete(address); // Cleanup after handling
        }
    }
     
    async handleFullMessageFromMemory(address, chunks,rinfo, path, sessionId) {
         const fullMessage = chunks.map(chunk => Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk, 'utf8'));

      
        try {
            const request = JSON.parse(fullMessage);  
           
             const body = request.body || {};
     
             if (this.requestHandler) {
                console.log('Forwarding message to requestHandler');
 
            // Pass the request and body to the requestHandler
            const response = await this.requestHandler(request, body, sessionId,path);
     
            // Send the response back to the client
            const encryptedResponse = this.encryptMessage(JSON.stringify(response));
                this.udpResponseSocket.send(encryptedResponse, rinfo.port, rinfo.address, (err) => {
                    if (err) {
                        console.error('Error sending response:', err);
                    } else {
                        console.log('Response sent successfully for full message');
                    }
                });
            } else {
                console.log('No request handler set for full message');
            }
        } catch (error) {
            console.error('Error handling full message:', error);
        } finally {
        // Remove the stored data for this message
        this.chunkStore.delete(address);
        }
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
        try {

        const parts = encryptedData.split(':');
        const [encryptedKeyBase64, iv, encrypted, authTag] = parts;

        if (parts.length !== 4) throw new Error("Invalid encrypted data format");


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

    } catch (error) {
        console.error("Decryption error:", error);
        this.sendError(null, "FRAME_ENCODING_ERROR", "Invalid frame encoding.");
        return null;
    }
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
    sendAck(rinfo, streamId, chunkNumber, frameType = "ACK") {
         const MAX_ACK_RETRIES = 5;
    
        let retries = 0;
    
        const sendAckMessage = () => {
            const ackMessage = JSON.stringify({
                frameType,
                streamId,
                chunkNumber,
                type: "ACK",
                windowSize: this.maxWindowSize - this.bytesInFlight, // Remaining space in the window
                timestamp: Date.now(),  // Add a timestamp
            });
    
            const encryptedAck = this.encryptMessage(ackMessage);
    
            this.udpServer.send(encryptedAck, rinfo.port, rinfo.address, (err) => {
                if (err) {
                    console.error(`Error sending ACK for chunk ${chunkNumber}:`, err);
    
                    if (retries < MAX_ACK_RETRIES) {
                        retries++;
                        console.log(`Retrying to send ACK for chunk ${chunkNumber} (Attempt ${retries}/${MAX_ACK_RETRIES})`);
                        setTimeout(sendAckMessage, 200); // Retry after 200ms
                    } else {
                        console.error(`Failed to send ACK for chunk ${chunkNumber} after ${MAX_ACK_RETRIES} attempts.`);
                    }
                } else {
                    console.log(`ACK sent for chunk ${chunkNumber} of stream ${streamId}`);
                }
            });
        };
    
        sendAckMessage();
    }
    
     
    
    compressHeaders(headers) {
    
        return this.qpack.compressHeaders(headers);

    }
    
    
    decompressHeaders(headers) {
        try {
            return this.qpack.decompressHeaders(headers);
        } catch (error) {
            console.error('Error during header decompression:', error);
            throw error;
        }
    }
    
    handleSettingsFrame(settings) {
        if (settings.maxTableSize) {
            this.dynamicTable.maxSize = settings.maxTableSize; // Update the size of the dynamic table
            console.log(`Dynamic table size updated to: ${settings.maxTableSize}`);
        }
    }
    
    async sendResponse(rinfo, sessionId, streamId, response) {
        // Compress headers
        const compressedHeaders = this.compressHeaders(response.headers);
    
        const responseMessage = JSON.stringify({
            streamId,
            type: 'RESPONSE',
            headers: compressedHeaders,
            body: response.body
        });
    
        const encryptedResponse = this.encryptMessage(responseMessage);
    
        // Send the encrypted response
        this.udpServer.send(encryptedResponse, rinfo.port, rinfo.address, (err) => {
            if (err) {
                console.error(`Error sending response for stream ${streamId}:`, err);
            } else {
                console.log(`Response sent successfully for stream ${streamId}`);
            }
        });
    }
    handleTimeoutOrLoss() {
        this.ssthresh = Math.max(this.congestionWindow / 2, 1024); // Update threshold
        this.congestionWindow = 1024; // Reset to minimum window size
        this.retransmissionCount = (this.retransmissionCount || 0) + 1; // Increment timeout count
        if (this.retransmissionCount > MAX_RETRIES) {
            console.error('Max retransmission attempts reached. Closing connection.');
            this.closeConnection();
            return; // Prevent further actions after connection closure
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

    reconstructStream(streamId) {
        const chunks = this.receivedChunks.get(streamId);
        if (!chunks) {
            throw new Error(`No chunks found for stream ${streamId}`);
        }
    
        const sortedChunks = Array.from(chunks.values()).sort((a, b) => a.chunkNumber - b.chunkNumber);
    
        // Identify missing chunks
        const missingChunks = [];
        for (let i = 0; i < sortedChunks.length; i++) {
            if (!chunks.has(i)) {
                missingChunks.push(i);
            }
        }
    
        if (missingChunks.length > 0) {
            console.error(`Missing chunks for stream ${streamId}:`, missingChunks);
            this.requestMissingChunks(streamId, missingChunks); // Request the missing chunks
            return null; // Message reconstruction failed
        }
    
        // Reconstruct the full message
        return sortedChunks.map(c => c.data).join('');
    }
    
    

    handleChunk(chunk) {
        const { streamId, chunkNumber, totalChunks, data } = chunk;
    
        if (!this.receivedChunks.has(streamId)) {
            this.receivedChunks.set(streamId, new Map());
        }
    
        this.receivedChunks.get(streamId).set(chunkNumber, { streamId, chunkNumber, data });
    
        console.log(`Chunk ${chunkNumber} of ${totalChunks} received for stream ${streamId}`);
    
        // Check if all chunks have been received
        const receivedChunks = Array.from(this.receivedChunks.get(streamId).keys());
        if (receivedChunks.length === totalChunks) {
            console.log(`All chunks received for stream ${streamId}. Reconstructing message...`);
            const fullMessage = this.reconstructStream(streamId);
            console.log(`Full message for stream ${streamId}:`, fullMessage);
    
            // Remove chunks after reconstructing the message

            this.receivedChunks.delete(streamId);
    
            // Process the complete message
            this.processFullMessage(streamId, fullMessage);
        }
    }
    
    // requestMissingChunks(streamId, missingChunks) {
    //     missingChunks.forEach(chunkNumber => {
    //         console.log(`Requesting missing chunk ${chunkNumber} for stream ${streamId}`);
    //           // Send a request for the missing chunk
    //     // You can send the request via UDP here
    //     });
    // }
    requestMissingChunks(streamId, missingChunks) {
        // Loop through each missing chunk
        missingChunks.forEach(chunkNumber => {
            console.log(`Requesting missing chunk ${chunkNumber} for stream ${streamId}`);
    
            // Create the request packet for the missing chunk
            const requestPacket = JSON.stringify({
                frameType: "MISSING_CHUNK_REQUEST", // Frame type for requesting missing chunks
                streamId: streamId,               // Identify the stream
                chunkNumber: chunkNumber,         // Specify the missing chunk
                timestamp: Date.now(),            // Add a timestamp for tracking
            });
    
            // Encrypt the request packet
            const encryptedRequest = this.encryptMessage(requestPacket);
    
            // Send the request packet via UDP
            this.udpClient.send(encryptedRequest, this.udpPort, this.address, (err) => {
                if (err) {
                    console.error(`Error sending request for missing chunk ${chunkNumber} of stream ${streamId}:`, err);
                } else {
                    console.log(`Request for missing chunk ${chunkNumber} of stream ${streamId} sent successfully.`);
                }
            });
        });
    }
    
    processFullMessage(streamId, fullMessage) {
        console.log(`Processing full message for stream ${streamId}:`, fullMessage);

       
        
        // Process the request
        const request = JSON.parse(fullMessage);
        const response = this.generateResponse(request);  // Function to generate the response
        
        // Send the response
        this.sendResponse(request.rinfo, request.sessionId, streamId, response);
    }
    
}

module.exports = HttpServer;
