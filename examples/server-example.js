const HttpServer = require('http3-package/src/core/httpServer');

const server = new HttpServer('127.0.0.1', 4434, '/home/mostafa/Downloads/github/1/example/key/public_key.pem', '/home/mostafa/Downloads/github/1/example/key/private_key.pem');

server.setRequestHandler(async (request) => {
    console.log('Received request:', request);
    console.log("request", request)

    // Process the request and send a response
    try {
        let response;

        if (request.method === 'GET') {
            response = {body: 'Hello, HTTP/3 with UDP! (GET)', data: await handleData(request.query)};
        } else if (request.method === 'POST') {
            response = {body: 'Data received and processed! (POST)', data: await handleData(request.payload)};
        } else if (request.method === 'PUT') {
            response = {body: 'Data updated! (PUT)', data: await handleData(request.payload)};
        } else if (request.method === 'DELETE') {
            response = {body: 'Data deleted! (DELETE)', data: await handleData(request.query)};
        } else {
            response = {body: 'Unsupported method'};
        }

        console.log('Sending response:', response);
        return response;
    } catch (error) {
        console.error('Error processing request:', error);
        return {body: 'Internal server error'};
    }
});

// Example handleData method for handling data
async function handleData(data) {
    // Processing data
    return new Promise((resolve) => {
        setTimeout(() => {
            resolve(`Processed data: ${JSON.stringify(data)}`);
        }, 1000);
    });
}

console.log('Server is running');
