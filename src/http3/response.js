class Http3Response {
    constructor(stream, encryption) {
        this.stream = stream;
        this.encryption = encryption;
    }

    writeHead(statusCode, headers) {
        let headerString = `HTTP/3 ${statusCode}\r\n`;
        for (const header in headers) {
            headerString += `${header}: ${headers[header]}\r\n`;
        }
        headerString += '\r\n';
        const encryptedHeader = this.encryption.encrypt(headerString);
        this.stream.write(encryptedHeader.encryptedData);
    }

    end(body) {
        const encryptedBody = this.encryption.encrypt(body);
        this.stream.end(encryptedBody.encryptedData);
    }
}

module.exports = Http3Response;
