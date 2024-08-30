

# HTTP/3 Node.js Package

This package provides an implementation of HTTP/3 over UDP using Node.js. It allows you to create secure, encrypted communication channels between clients and servers using the latest HTTP/3 protocol.

## Features

- **HTTP/3 over UDP**: Implements the latest HTTP/3 protocol with UDP.
- **TLS Encryption**: Secure communication using TLS.
- **Session Management**: Supports session handling with session IDs.
- **Chunked Messaging**: Efficient handling of large messages by sending them in chunks.
- **Rate Limiting**: Implements rate limiting to control the flow of requests.

## Installation

You can install this package using npm:

```bash
npm install http3-package
```

## Usage

### Server Example

```javascript
const Http3Server = require('http3-package/src/core/http3server');

const server = new Http3Server('127.0.0.1', 4434, 'path/to/server-cert.pem', 'path/to/server-key.pem');

server.setRequestHandler(async (request) => {
    console.log('Received request:', request);

    // Handle request based on method
    let response;
    if (request.method === 'GET') {
        response = {body: 'Hello, HTTP/3 with UDP! (GET)'};
    } else if (request.method === 'POST') {
        response = {body: 'Data received and processed! (POST)', data: request.payload};
    }
    return response;
});

console.log('HTTP/3 server is running');
```

### Client Example

```javascript
const Http3Client = require('http3-package/src/core/http3client');

const client = new Http3Client('localhost', 4434, 'path/to/client-cert.pem', 'path/to/client-key.pem');

const sendRequest = async () => {
    await client.initializeSession();

    const method = 'POST';
    const path = '/example';
    const headers = {
        'Content-Type': 'application/json'
    };
    const body = {
        key: 'value'
    };

    await client.sendHttpRequest(method, path, headers, body);
    console.log('HTTP/3 request sent.');
};

sendRequest();
```

## Configuration

Before starting the HTTP/3 server and client, you need to set up the stunnel configurations.

### 1. Environment Variables

You can set the following environment variables or you will be prompted to enter them during the setup:

- `SERVER_ACCEPT`: The server's accept address (e.g., `127.0.0.1:5000`).
- `SERVER_CONNECT`: The server's connect address (e.g., `127.0.0.1:4434`).
- `SERVER_CERT`: Path to the server's certificate file (e.g., `path/to/server-cert.pem`).
- `SERVER_KEY`: Path to the server's private key file (e.g., `path/to/server-key.pem`).
- `CLIENT_ACCEPT`: The client's accept address (e.g., `127.0.0.1:5001`).
- `CLIENT_CONNECT`: The client's connect address (e.g., `127.0.0.1:5000`).
- `CLIENT_CERT`: Path to the client's certificate file (e.g., `path/to/client-cert.pem`).
- `CLIENT_KEY`: Path to the client's private key file (e.g., `path/to/client-key.pem`).

### 2. Running the Setup Script

Run the following command to generate the stunnel configuration files:

```bash
node scripts/setupStunnel.js
```

This script will create the necessary stunnel configuration files based on your environment variables or inputs.

### Running the Server and Client

After setting up the stunnel configuration, you can start the server and client as follows:

- **Starting the Server**:
  ```bash
  node server-example.js
  ```
- **Starting the Client**:
  ```bash
  node client-example.js
  ```

## Security Considerations

- Ensure that your TLS certificates are securely generated and stored.
- Regularly update your dependencies to ensure that your implementation remains secure.

## Contributing

If you'd like to contribute to this project, feel free to fork the repository and submit a pull request.

## License

This project is licensed under the MIT License.

---

### **Understanding `HttpServer` and `HttpClient` Code for HTTP/3**

This section explains the `HttpServer` and `HttpClient` codes to help you understand the mechanism and functionality of HTTP/3. Each function’s purpose and operation are detailed to give you a better grasp of the interaction between the server and the client.

### **HttpServer:**

This class implements an HTTP/3 server using UDP in Node.js. The server manages incoming connections, tracks sessions, and processes incoming requests with secure communication.

#### **Key Functions and Features:**

1. **`constructor(address, port, publicKeyPath, privateKeyPath)`**:
   - **Purpose**: Initializes the server with an IP address, port, and paths to the public and private keys for TLS encryption.
   - **How it Works**: Sets up the UDP server, prepares for secure communication, and stores sessions.

2. **`setupUDPServer()`**:
   - **Purpose**: Sets up the UDP server to receive messages and manage connections.
   - **How it Works**: Receives incoming messages, decrypts them, and checks if the session is valid.

3. **`handleRequest(rinfo, data, sessionId)`**:
   - **Purpose**: Manages incoming requests by checking the session and decrypting the message.
   - **How it Works**: If the session is valid, the request is processed, and an encrypted response is sent back to the client.

4. **`encryptMessage(message)`**:
   - **Purpose**: Encrypts the message using AES-256-GCM and RSA.
   - **How it Works**: Encrypts the message using the public key for secure communication.

5. **`decryptMessage(encryptedData)`**:
   - **Purpose**: Decrypts incoming messages using AES and the private key.
   - **How it Works**: Decrypts the client’s encrypted message and extracts the information.

---

### **HttpClient:**

The `HttpClient` class implements an HTTP/3 client that uses UDP for secure communication with the server. This client can send HTTP requests, manage sessions, and use encryption for secure communications.

#### **Key Functions and Features:**

1. **`constructor(address, port, publicKeyPath, privateKeyPath)`**:
   - **Purpose**: Initializes the client with the server’s address, port, and paths to the public and private keys for TLS encryption.
   - **How it Works**: Establishes communication with the server via a UDP socket and prepares for secure communications.

2. **`initializeSession()`**:
   - **Purpose**: Starts a session by sending an initial handshake message to the server.
   - **How it Works**: Sends an encrypted handshake message to the server and waits to receive a session ID.

3. **`sendHttpRequest(method, path, headers, body)`**:
   - **Purpose**: Sends an HTTP request to the server with the specified method and data.
   - **How it Works**: The request is encrypted and, if necessary, sent in chunks to ensure secure and efficient data transmission.

4. **`sendChunkedMessage(message, chunkSize)`**:
   - **Purpose**: Splits large messages into smaller chunks for transmission.
   - **How it Works**: Divides the message into smaller chunks, encrypts, and sends each chunk separately.

5. **`encryptMessage(message)`**:
   - **Purpose**: Encrypts a message for secure transmission to the server.
   - **How it Works**: Uses AES-256-GCM for content encryption and RSA for key exchange.

6. **`decryptMessage(encryptedData)`**:
   - **Purpose**: Decrypts the encrypted messages received from the server.
   - **How it Works**: Decrypts the encrypted message using the client’s private key to recover the original content.

---

### **Explaining the `setupStunnel` Code:**

The `setupStunnel` code configures stunnel, a tool used for creating TLS tunnels.

1. **`getUserInput()`**:
   - **Purpose**: Collects user input for setting server and client addresses, paths to encryption keys, and accept/connect addresses.
   - **How it Works**: Uses user inputs or environment variables to gather the necessary configuration settings.

2. **`setupStunnel()`**:
   - **Purpose**: Configures stunnel files for the server and client using user input.
   - **How it Works**: Replaces placeholders in template files with user input values and generates final configuration files to run stunnel.


