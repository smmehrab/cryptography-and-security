"use strict";

const { getRandomValues, subtle } = require('crypto');
const base64url = require('base64url');

class Util {

  /* Others *****************************************************************/

  static encoder = new TextEncoder();
  static decoder = new TextDecoder();

  static generateRandomSalt (bytes=16) {
    // Base64 Representation
    return Util.arrayBufferToBase64(getRandomValues(new Uint8Array(bytes)));
  }

  static generateRandomBase64Noise() {
    // Max 100 Base64 Characters
    let noiseLength = Math.floor(Math.random() * 75);
    return Util.arrayBufferToBase64(getRandomValues(new Uint8Array(noiseLength)));
  }

  static stringToByteArray (str) {
    return Util.encoder.encode(str)
  }
  
  static byteArrayToString (arr) {
    return Util.decoder.decode(arr);
  }
  
  static untypedToTypedArray (arr) {
    return new Uint8Array(arr);
  }
  
  static bufferToUntypedArray (arr) {
    return Array.from(new Uint8Array(arr));
  }

  static arrayBufferToBase64 (arrayBuffer) {
    return base64url.encode(Buffer.from(arrayBuffer));
  }

  static base64ToArrayBuffer(base64String) {
    const buffer = Buffer.from(base64url.toBuffer(base64String));
    return buffer.buffer.slice(buffer.byteOffset, buffer.byteOffset + buffer.byteLength);
  }

  /* Key Generators *****************************************************/

  static async generateMasterKey(password, salt=null, iterations=100000) {

    // Password to CryptoKey
    let passwordCryptoKey = await subtle.importKey(
      "raw",
      password,
      { 
        name: "PBKDF2",
        hash: "SHA-256",
      },
      false,
      ["deriveKey"]
    );

    //  Master Key from Password CryptoKey
    salt = salt || Util.generateRandomSalt();
    let masterKey = await subtle.deriveKey(
      {
        "name": "PBKDF2",
        salt: salt,
        "iterations": iterations,
        "hash": "SHA-256"
      },
      passwordCryptoKey,
      {
        name: "HMAC",
        hash: { name: "SHA-256" },
        length: 128,
      },
      false,
      ["sign", "verify"]
    );

    return [salt, masterKey];

  }

  static async generateHMACKey(masterKey, HMAC_PHRASE) {

    let hmacRawKey = await subtle.sign(
      "HMAC",
      masterKey,
      HMAC_PHRASE
    );

    let HMAC_KEY = await subtle.importKey(
      "raw",
      hmacRawKey,
      {
        name: "HMAC",
        hash: "SHA-256",
      },
      false,
      ["sign"]
    );

    return HMAC_KEY;
  }

  static async generateAESKey(masterKey, AESGCM_PHRASE) {

    let aesRawKey = await subtle.sign(
      "HMAC",
      masterKey,
      AESGCM_PHRASE
    );

    let AES_KEY = await subtle.importKey(
      "raw",
      aesRawKey,
      { name: "AES-GCM", },
      false,
      ["encrypt", "decrypt"]
    );

    return AES_KEY;
  }

  /* HMAC ****************************************************************/

  static async HMAC(key, x) {
    let xHMAC = await subtle.sign("HMAC", key, x);
    xHMAC = Util.arrayBufferToBase64(xHMAC);
    return xHMAC;
  }

  /* Encryption/Decryption ***********************************************/

  static async encryptPassword(nameHMAC, password, AES_KEY) {

    // IV = 24 Bytes = 192 Bits = 32 Base64 Characters
    let iv = Util.generateRandomSalt(24);

    // Resistent to swap attacks
    let passwordData = password + nameHMAC + Util.generateRandomBase64Noise();

    // Encryption
    let encryptedPasswordData = await subtle.encrypt(
      {
        name: "AES-GCM",
        iv: iv,
      },
      AES_KEY,
      passwordData
    );

    encryptedPasswordData = Util.arrayBufferToBase64(encryptedPasswordData);
    encryptedPasswordData = iv + encryptedPasswordData;

    // Encrypted Password Data = IV (Base64) + Encrypt (Password + nameHMAC + Random Noise Padding)
    return encryptedPasswordData;
  }

  static async decryptPassword(encryptedPasswordData, AES_KEY) {
    // First 32 Base64 Characters
    let iv = encryptedPasswordData.slice(0, 32);

    // Prepare for decryption
    encryptedPasswordData = encryptedPasswordData.slice(32);
    encryptedPasswordData = Util.base64ToArrayBuffer(encryptedPasswordData);

    // Decryption
    let passwordData = await subtle.decrypt(
      {
        name: "AES-GCM",
        iv: iv,
      },
      AES_KEY,
      encryptedPasswordData
    );

    passwordData = Util.byteArrayToString(passwordData);
    return passwordData;
  }

  /* Master Password Phrase ***********************************************/

  static async sign_master_password_phrase(masterKey, masterPasswordPhrase) {

    let masterPasswordPhraseSigned = await subtle.sign(
      "HMAC",
      masterKey,
      masterPasswordPhrase
    );

    return Util.untypedToTypedArray(masterPasswordPhraseSigned);
  }

  static async dict_to_unit8array(dic) {
    var dicValueArray = Object.keys(dic).map(key => dic[key]);
    return new Uint8Array(dicValueArray);
  }

  static async check_master_password_phrase(masterKey, masterPasswordPhraseSigned, masterPasswordPhrase) {
    let validity = await subtle.verify(
      "HMAC",
      masterKey,
      await Util.dict_to_unit8array(masterPasswordPhraseSigned),
      masterPasswordPhrase
    );

    return validity;
  }

}

module.exports = Util;
