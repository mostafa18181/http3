const crypto = require('crypto');

class Encryption {
    constructor(algorithm = 'aes-256-cbc', key, iv) {
        this.algorithm = algorithm;
        this.key = key || crypto.randomBytes(32); // AES-256 requires a 32-byte key
        this.iv = iv || crypto.randomBytes(16);   // AES-256 requires a 16-byte IV
    }

    static generateKey() {
        return crypto.randomBytes(32).toString('hex'); // Generates a 32-byte key for AES-256
    }

    static generateIv() {
        return crypto.randomBytes(16).toString('hex'); // Generates a 16-byte IV for AES-256
    }

    encrypt(text) {
        const cipher = crypto.createCipheriv(this.algorithm, this.key, this.iv);
        let encrypted = cipher.update(text, 'utf8', 'hex');
        encrypted += cipher.final('hex');
        return {
            iv: this.iv.toString('hex'),
            encryptedData: encrypted
        };
    }

    decrypt(encryptedData, iv) {
        try {

            const decipher = crypto.createDecipheriv(this.algorithm, this.key, Buffer.from(iv, 'hex'));
            let decrypted = decipher.update(encryptedData, 'hex', 'utf8');
            decrypted += decipher.final('utf8');
            return decrypted;
        } catch (error) {
            console.error('Decryption failed:', error.message);
            return null;
        }
    }
}

module.exports = Encryption;
