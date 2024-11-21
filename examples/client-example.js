
const HttpClient = require('../src/core/httpClient');

const sendRequests = async () => {
    const client = new HttpClient(
        '127.0.0.1',
        4434,
        'public_key.pem',
        'private_key.pem'
    );

    try {
        // Start session
        await client.initializeSession();

        // Test requests
        const tests = [
            {
                method: 'POST',
                path: '/submit',
                headers: [
                    { type: 'literal', header: { key: 'Content-Type', value: 'application/json' } },
                    { type: 'literal', header: { key: 'Authorization', value: 'Bearer token123' } }
                ],
                body: { data: 'Simple test payload' }
            },
            {
                method: 'POST',
                path: '/process',
                headers: [
                    { type: 'indexed', index: 0, table: 'dynamic' },
                    { type: 'indexed', index: 1, table: 'dynamic' }
                ],
                body: { action: 'process', value: 42 }
            },
            {
                method: 'GET',
                path: '/unknown',
                headers: [],
                body: null
            },
            {
                method: 'POST',
                path: '/error',
                headers: [
                    { type: 'literal', header: { key: 'Content-Type', value: 'application/json' } }
                ],
                body: { cause: 'Testing error response' }
            }
        ];

        // Send requests
        for (const test of tests) {
            try {
                await client.sendHttpRequest(test.method, test.path, test.headers, test.body);
                console.log(`${test.method} request to ${test.path} sent successfully.`);
            } catch (error) {
                console.error(`Error sending ${test.method} request to ${test.path}:`, error);
            }
        }

        console.log('All requests sent successfully.');
    } catch (error) {
        console.error('Error during client operation:', error);
    }  finally {
        setTimeout(() => {
            if (client.isSocketActive()) {
                console.log('Closing active client...');
                client.udpClient.close();
                client.udpClient = null;
            } else {
                console.log('Client socket is already inactive.');
            }
        }, 5000);
    }
    
};

sendRequests();
