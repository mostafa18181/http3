const HttpClient = require('http3-package/src/core/httpClient');
const client = new HttpClient('localhost', 4434, '/example/key/public_key.pem', '/example/key/private_key.pem');

const sendRequest = async () => {
    try {
        await client.initializeSession();

        const method = 'POST'; // 'GET', 'POST', 'PUT', 'DELETE'
        const path = '/example';
        const headers = {
            'Content-Type': 'application/json'
        };
        const body = {
            key: 'value'
        };

        await client.sendHttpRequest(method, path, headers, body);
        console.log('HTTP request sent.');

        setTimeout(() => {
            console.log('Closing client after waiting for responses.');
            client.udpClient.close();
        }, 10000);
    } catch (error) {
        console.error('Error sending HTTP request:', error);
    }
};

sendRequest();
