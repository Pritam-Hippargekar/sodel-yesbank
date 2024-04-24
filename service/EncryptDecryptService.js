const fs = require('fs');
const rsaSpecification = require("./RsaEcbPkcs1PaddingService");
const aesSpecification = require("./AesGcmNoPaddingService");
const CustomError = require("../exceptions/CustomError");

const encryptRequest = (plainPartnerKey, plainRequestBody, partnerPrivateKey, bankPublicKey, version) => {
    let securitykey = aesSpecification.generateKey(32);
    let initVector = aesSpecification.generateIv(16);
    let encryptKey = rsaSpecification.rsaEncrypt(securitykey, bankPublicKey);
    let encryptPartner = rsaSpecification.rsaEncrypt(plainPartnerKey, bankPublicKey);
    var encryptBody;
    if(version === "v2") {
        encryptBody = aesSpecification.aesEncrypt(plainRequestBody, securitykey, initVector);
    } else {
        throw new CustomError('version not sepecified', 'YPP-004');  
    }
    let requestToken = rsaSpecification.signData(plainRequestBody, fs.readFileSync(partnerPrivateKey, "utf8"));
    return {
        encryptedSecretKey: encryptKey,
        plainRequestIv: initVector,
        encryptedPartnerKey: encryptPartner,
        encryptRequestBody: encryptBody,
        requestToken: requestToken
    }
}

const decryptResponse = (responseHash, responseIv, responseSecretKey, responseBody, partnerPrivateKey, bankPublicKey, version) => {
    let decryptKey = rsaSpecification.rsaDecrypt(responseSecretKey, partnerPrivateKey);
    var encryptBody;
    if(version === "v2"){
        encryptBody = aesSpecification.aesDecrypt(responseBody, decryptKey, responseIv);
    } else {
        throw new CustomError('version not sepecified', 'YPP-004');  
    }
    let result = rsaSpecification.verifyData(encryptBody, responseHash, fs.readFileSync(bankPublicKey, "utf8"));
    return {
        result: result,
        encryptBody: encryptBody
    };
}

// const encryptRequest = (plainPartnerKey, plainRequestBody, partnerPrivateKey, bankPublicKey, version) => {
//     let secretKey = aesSpecification.generateKey(16);
//     let initVector = aesSpecification.generateIv(16);
//     let encryptKey = rsaSpecification.rsaEncrypt(secretKey, bankPublicKey);
//     let encryptPartner = rsaSpecification.rsaEncrypt(plainPartnerKey, bankPublicKey);
//     var encryptBody;
//     if(version === "v1") {
//         encryptBody = aesSpecification.aesEncrypt(plainRequestBody, secretKey, initVector);
//     } else {
//         throw new CustomError('version not sepecified', 'YPP-004');  
//     }
//     let requestToken = rsaSpecification.signData(plainRequestBody, fs.readFileSync(partnerPrivateKey, "utf8"));
//     return {
//         encryptedSecretKey: encryptKey,
//         plainRequestIv: initVector,
//         encryptedPartnerKey: encryptPartner,
//         encryptRequestBody: encryptBody,
//         requestToken: requestToken
//     }
// }

// const decryptResponse = (responseHash, responseIv, responseSecretKey, responseBody, partnerPrivateKey, bankPublicKey, version) => {
//     let decryptKey = rsaSpecification.rsaDecrypt(responseSecretKey, partnerPrivateKey);
//     var encryptBody;
//     if(version === "v1"){
//         encryptBody = aesSpecification.aesDecrypt(responseBody, decryptKey, responseIv);
//     }
//     let result = rsaSpecification.verifyData(encryptBody, responseHash, fs.readFileSync(bankPublicKey, "utf8"));
//     return {
//         result: result,
//         encryptBody: encryptBody
//     };
// }

module.exports = {
    encryptRequest, decryptResponse
}