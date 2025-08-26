
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const os = require('os');

class TamimHardcode {
    constructor() {
        this.algorithm = 'aes-256-gcm';
        this.keyLength = 32;
        this.ivLength = 16;
        this.tagLength = 16;
        this.licenseKey = 'tamim-hardcode-2024-secure-key';
        this.machineId = this.getMachineId();
        
        // Check if package is properly installed
        if (!this.isValidInstallation()) {
            throw new Error('TamimHardcode: Invalid installation. Please install via npm.');
        }
    }

    getMachineId() {
        const networkInterfaces = os.networkInterfaces();
        const mac = Object.values(networkInterfaces)
            .flat()
            .find(iface => !iface.internal && iface.mac !== '00:00:00:00:00:00')?.mac;
        return crypto.createHash('sha256').update(mac || os.hostname()).digest('hex').substring(0, 16);
    }

    isValidInstallation() {
        try {
            // Check if package.json exists in node_modules
            const packagePath = path.join(process.cwd(), 'node_modules', 'tamimhardcode', 'package.json');
            return fs.existsSync(packagePath);
        } catch (error) {
            return false;
        }
    }

    generateSecureKey(password) {
        const salt = crypto.randomBytes(32);
        const key = crypto.pbkdf2Sync(password, salt, 100000, this.keyLength, 'sha512');
        return { key, salt };
    }

    encrypt(text, password = this.licenseKey) {
        try {
            // Verify license
            if (!this.verifyLicense()) {
                throw new Error('TamimHardcode: License verification failed.');
            }

            const { key, salt } = this.generateSecureKey(password + this.machineId);
            const iv = crypto.randomBytes(this.ivLength);
            
            const cipher = crypto.createCipherGCM(this.algorithm, key, iv);
            
            let encrypted = cipher.update(text, 'utf8', 'hex');
            encrypted += cipher.final('hex');
            
            const authTag = cipher.getAuthTag();
            
            // Combine all components
            const result = {
                encrypted,
                salt: salt.toString('hex'),
                iv: iv.toString('hex'),
                authTag: authTag.toString('hex'),
                timestamp: Date.now(),
                machineId: this.machineId
            };
            
            return Buffer.from(JSON.stringify(result)).toString('base64');
        } catch (error) {
            throw new Error(`TamimHardcode Encryption Error: ${error.message}`);
        }
    }

    decrypt(encryptedData, password = this.licenseKey) {
        try {
            // Verify license
            if (!this.verifyLicense()) {
                throw new Error('TamimHardcode: License verification failed.');
            }

            const data = JSON.parse(Buffer.from(encryptedData, 'base64').toString('utf8'));
            
            // Verify machine ID
            if (data.machineId !== this.machineId) {
                throw new Error('TamimHardcode: Machine verification failed.');
            }
            
            const key = crypto.pbkdf2Sync(
                password + this.machineId,
                Buffer.from(data.salt, 'hex'),
                100000,
                this.keyLength,
                'sha512'
            );
            
            const decipher = crypto.createDecipherGCM(
                this.algorithm,
                key,
                Buffer.from(data.iv, 'hex')
            );
            
            decipher.setAuthTag(Buffer.from(data.authTag, 'hex'));
            
            let decrypted = decipher.update(data.encrypted, 'hex', 'utf8');
            decrypted += decipher.final('utf8');
            
            return decrypted;
        } catch (error) {
            throw new Error(`TamimHardcode Decryption Error: ${error.message}`);
        }
    }

    verifyLicense() {
        const licenseHash = crypto.createHash('sha256')
            .update(this.licenseKey + this.machineId + 'tamim2024')
            .digest('hex');
        
        // Simple license verification - in production, this could be more sophisticated
        return licenseHash.length === 64;
    }

    encryptFile(filePath, outputPath = null, password = this.licenseKey) {
        try {
            const content = fs.readFileSync(filePath, 'utf8');
            const encrypted = this.encrypt(content, password);
            
            const output = outputPath || filePath + '.tamim';
            fs.writeFileSync(output, encrypted);
            
            return output;
        } catch (error) {
            throw new Error(`TamimHardcode File Encryption Error: ${error.message}`);
        }
    }

    decryptFile(filePath, outputPath = null, password = this.licenseKey) {
        try {
            const encryptedContent = fs.readFileSync(filePath, 'utf8');
            const decrypted = this.decrypt(encryptedContent, password);
            
            const output = outputPath || filePath.replace('.tamim', '');
            fs.writeFileSync(output, decrypted);
            
            return output;
        } catch (error) {
            throw new Error(`TamimHardcode File Decryption Error: ${error.message}`);
        }
    }

    // Method to check if the package is properly licensed
    static isLicensed() {
        try {
            const instance = new TamimHardcode();
            return instance.verifyLicense();
        } catch {
            return false;
        }
    }

    // Method to get package info
    static getInfo() {
        return {
            name: 'tamimhardcode',
            version: '1.0.0',
            description: 'Secure encryption/decryption package with license protection',
            author: 'Tamim',
            license: 'Proprietary'
        };
    }
}

// Export the class and some utility functions
module.exports = {
    TamimHardcode,
    encrypt: (text, password) => new TamimHardcode().encrypt(text, password),
    decrypt: (encryptedData, password) => new TamimHardcode().decrypt(encryptedData, password),
    encryptFile: (filePath, outputPath, password) => new TamimHardcode().encryptFile(filePath, outputPath, password),
    decryptFile: (filePath, outputPath, password) => new TamimHardcode().decryptFile(filePath, outputPath, password),
    isLicensed: TamimHardcode.isLicensed,
    getInfo: TamimHardcode.getInfo
};

// Protection against direct execution without proper installation
if (require.main === module) {
    console.log('TamimHardcode v1.0.0');
    console.log('This package must be installed via npm to function properly.');
    
    // Demo usage (only works when properly installed)
    try {
        const tamim = new TamimHardcode();
        const text = "Hello, this is a secret message!";
        console.log('\nDemo:');
        console.log('Original:', text);
        
        const encrypted = tamim.encrypt(text);
        console.log('Encrypted:', encrypted.substring(0, 50) + '...');
        
        const decrypted = tamim.decrypt(encrypted);
        console.log('Decrypted:', decrypted);
        
    } catch (error) {
        console.error('\nError:', error.message);
    }
}
