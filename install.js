const fs = require('fs');
const os = require('os');
const path = require('path');

function getUserInput() {
    return {
        serverAccept: process.env.SERVER_ACCEPT || prompt('Enter server accept address (default: 127.0.0.1:5000): ', '127.0.0.1:5000'),
        serverConnect: process.env.SERVER_CONNECT || prompt('Enter server connect address (default: 127.0.0.1:4434): ', '127.0.0.1:4434'),
        serverCert: process.env.SERVER_CERT || prompt('Enter server certificate path (default: path/to/server-cert.pem): ', '/path/to/server-cert.pem'),
        serverKey: process.env.SERVER_KEY || prompt('Enter server key path (default: path/to/server-key.pem): ', '/path/to/server-key.pem'),
        clientAccept: process.env.CLIENT_ACCEPT || prompt('Enter client accept address (default: 127.0.0.1:5001): ', '127.0.0.1:5001'),
        clientConnect: process.env.CLIENT_CONNECT || prompt('Enter client connect address (default: 127.0.0.1:5000): ', '127.0.0.1:5000'),
        clientCert: process.env.CLIENT_CERT || prompt('Enter client certificate path (default: path/to/client-cert.pem): ', '/path/to/client-cert.pem'),
        clientKey: process.env.CLIENT_KEY || prompt('Enter client key path (default: path/to/client-key.pem): ', '/path/to/client-key.pem')
    };
}

function setupStunnel() {
    const answers = getUserInput();

    const stunnelConfigServerTemplate = fs.readFileSync(path.join(__dirname, '../config/stunnelServer.conf.template'), 'utf8');
    const stunnelConfigClientTemplate = fs.readFileSync(path.join(__dirname, '../config/stunnelClient.conf.template'), 'utf8');

    const stunnelConfigServer = stunnelConfigServerTemplate
        .replace('{serverAccept}', answers.serverAccept)
        .replace('{serverConnect}', answers.serverConnect)
        .replace('{serverCert}', answers.serverCert)
        .replace('{serverKey}', answers.serverKey);

    const stunnelConfigClient = stunnelConfigClientTemplate
        .replace('{clientAccept}', answers.clientAccept)
        .replace('{clientConnect}', answers.clientConnect)
        .replace('{clientCert}', answers.clientCert)
        .replace('{clientKey}', answers.clientKey);

    const stunnelConfigPathServer = path.join(os.homedir(), 'stunnel-server.conf');
    const stunnelConfigPathClient = path.join(os.homedir(), 'stunnel-client.conf');

    fs.writeFileSync(stunnelConfigPathServer, stunnelConfigServer);
    console.log(`stunnel server configuration written to ${stunnelConfigPathServer}`);

    fs.writeFileSync(stunnelConfigPathClient, stunnelConfigClient);
    console.log(`stunnel client configuration written to ${stunnelConfigPathClient}`);

    console.log('Please start stunnel with the following commands:');
    console.log(`stunnel ${stunnelConfigPathServer}`);
    console.log(`stunnel ${stunnelConfigPathClient}`);
}

setupStunnel();
