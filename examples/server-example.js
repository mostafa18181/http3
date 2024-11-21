
const HttpServer = require('../src/core/httpServer');

const server = new HttpServer('127.0.0.1', 4434, 'public_key.pem', 'private_key.pem');

// Configure request handling
server.setRequestHandler(async (request, body, sessionId, path) => {
    console.log('Request handler registered:', path);

    switch (path) {
        case '/submit':
            return { success: true, message: 'Request processed successfully.' };
        case '/process':
            const processedData = await handleData(body);
            return { success: true, message: `Data processed: ${processedData}` };
        case '/error':
            return { success: false, message: 'Forced error response.' };
        default:
            return { success: false, message: 'Unknown path.' };
    }
});

// A sample method for processing data
async function handleData(data) {
    return new Promise((resolve) => {
        setTimeout(() => {
            resolve(`Processed data: ${JSON.stringify(data)}`);
        }, 1000);
    });
}

console.log('Server is running');
