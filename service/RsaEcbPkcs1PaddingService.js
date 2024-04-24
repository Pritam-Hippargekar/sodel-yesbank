const crypto = require('crypto');
const fs = require('fs');
const forge = require('node-forge');

const rsaEncrypt = (plainText, publicKeyFile) => {
    const publicObj = forge.pki.publicKeyFromPem(fs.readFileSync(publicKeyFile, 'utf8'));
    const bytes = publicObj.encrypt(plainText);
    return forge.util.encode64(bytes);
}

const rsaDecrypt = (cipherText, privateKeyFile) => {
    const privateObj = forge.pki.privateKeyFromPem(fs.readFileSync(privateKeyFile, 'utf8'));
    const bytes = forge.util.decode64(cipherText);
    return privateObj.decrypt(bytes);
}

const signData = (data, privateKey) => {
    const sign = crypto.createSign('RSA-SHA1');
    sign.update(data);
    sign.end();
    return sign.sign(privateKey, 'base64');
}

const verifyData = (data, signature, publicKey) => {
    const verify = crypto.createVerify('RSA-SHA1');
    verify.update(data);
    verify.end();
    return verify.verify(publicKey, signature, "base64");
}

module.exports = {
    signData, verifyData,
    rsaEncrypt, rsaDecrypt
}

