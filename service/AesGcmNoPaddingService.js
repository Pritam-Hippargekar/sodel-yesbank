const forge = require('node-forge');
const crypto = require('crypto');

const generateKey = (keySize) => {
    return crypto.createHash('sha512').update('fd85b494-aaaa').digest('base64').substr(0, keySize);
    //return crypto.randomBytes(keySize).toString('base64')
    //return forge.random.getBytesSync(keySize);
} 

const generateIv = (ivSize) => {
    return crypto.createHash('sha512').update('smslt').digest('base64').substr(0, ivSize);
    //return crypto.randomBytes(ivSize).toString('base64')
    //return forge.random.getBytesSync(ivSize);
}

const aesEncrypt = (plainText, secretKey, secretIv) => {
    const cipher = forge.cipher.createCipher('AES-GCM', secretKey);
    cipher.start({
        iv: secretIv, 
        tagLength: 128 
    });
    cipher.update(forge.util.createBuffer(plainText, 'utf8'));
    const result = cipher.finish();
    if (!result) {
        throw new Error(`Couldn't encrypt body: ${plainText}`);
    }
    const data = cipher.output.data; 
    const tag = cipher.mode.tag.data;
    return forge.util.encode64(data + tag);
}

const aesDecrypt = (cipherText, secretKey, secretIv) => { 
    const data = forge.util.decode64(cipherText); 
    const encryptData = data.slice(0, data.length - 16);
    const tag = data.slice(data.length - 16, data.length);
    const decipher = forge.cipher.createDecipher('AES-GCM', secretKey);
    decipher.start({
        iv: secretIv,
        tag: tag 
    });
    decipher.update(forge.util.createBuffer(encryptData));
    const result = decipher.finish();
    if (!result) {
        throw new Error(`Couldn't decrypt body: ${cipherText}`);
    }
    const bytes = decipher.output.getBytes(); 
    return forge.util.decodeUtf8(bytes);
}

module.exports = { 
    generateKey, generateIv, 
    aesEncrypt, aesDecrypt
}