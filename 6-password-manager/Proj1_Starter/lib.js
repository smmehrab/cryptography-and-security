"use strict";

const { getRandomValues, subtle } = require("crypto");
const base64url = require("base64url");

class Util {

  /* Others **************************************************************************/

  static encoder = new TextEncoder();
  static decoder = new TextDecoder();

  static generateRandomSalt(bytes = 16) {
    // Base64 Representation
    return Util.arrayBufferToBase64(getRandomValues(new Uint8Array(bytes)));
  }

  static generateRandomBase64Noise(maxBase64CharacterCount=100) {
    let maxByteCount = Math.ceil((maxBase64CharacterCount * 3) / 4);
    let noiseLength = Math.floor(Math.random() * maxByteCount);
    return Util.arrayBufferToBase64(getRandomValues(new Uint8Array(noiseLength)));
  }

  static stringToByteArray(str) {
    return Util.encoder.encode(str);
  }

  static byteArrayToString(arr) {
    return Util.decoder.decode(arr);
  }

  static untypedToTypedArray(arr) {
    return new Uint8Array(arr);
  }

  static bufferToUntypedArray(arr) {
    return Array.from(new Uint8Array(arr));
  }

  static arrayBufferToBase64(arrayBuffer) {
    return base64url.encode(Buffer.from(arrayBuffer));
  }

  static base64ToArrayBuffer(base64String) {
    const buffer = Buffer.from(base64url.toBuffer(base64String));
    return buffer.buffer.slice(buffer.byteOffset,buffer.byteOffset + buffer.byteLength);
  }

  /* Key Generators ******************************************************************/

  static async generateMasterKey(password, salt, iterations) {

    const HmacKeyGenParams = {
      name: 'HMAC',
      hash: 'SHA-256',
      length: 256,
    };

    const Pbkdf2Params = {
      name: "PBKDF2",
      salt: salt,
      iterations: iterations,
      hash: "SHA-256",
    }

    // Password to CryptoKey
    const passwordCryptoKey = await subtle.importKey(
      "raw",
      password,
      Pbkdf2Params,
      false,
      ["deriveKey"]
    );

    //  Password CryptoKey to Master Key
    const masterKey = await subtle.deriveKey(
      Pbkdf2Params,
      passwordCryptoKey,
      HmacKeyGenParams,
      false,
      ["sign", "verify"]
    );

    return [salt, masterKey];
  }

  static async generateHMACKey(masterKey, HMAC_KEY_DERIVATION_SALT) {

    const HmacKeyGenParams = {
      name: 'HMAC',
      hash: 'SHA-256',
      length: 256,
    };

    const HMAC_RAW_KEY = await subtle.sign("HMAC", masterKey, HMAC_KEY_DERIVATION_SALT);

    const HMAC_KEY = await subtle.importKey(
      "raw",
      HMAC_RAW_KEY,
      HmacKeyGenParams,
      false,
      ["sign"]
    );

    return HMAC_KEY;
  }

  static async generateAESKey(masterKey, AES_KEY_DERIVATION_SALT) {

    const AesKeyGenParams = {
      name: 'AES-GCM',
      length: 256,
    };

    const AES_RAW_KEY = await subtle.sign("HMAC", masterKey, AES_KEY_DERIVATION_SALT);

    const AES_KEY = await subtle.importKey(
      "raw",
      AES_RAW_KEY,
      AesKeyGenParams,
      false,
      ["encrypt", "decrypt"]
    );

    return AES_KEY;
  }

  /* HMAC ****************************************************************************/

  static async HMAC(key, x) {
    let xHMAC = await subtle.sign("HMAC", key, x);
    xHMAC = Util.arrayBufferToBase64(xHMAC);
    return xHMAC;
  }

  /* Encryption/Decryption ***********************************************************/

  static async encryptPassword(nameHMAC, password, AES_KEY) {
    // IV = 24 Bytes = 192 Bits = 32 Base64 Characters
    let iv = Util.generateRandomSalt(24);

    // Resistent to swap attacks
    let passwordData = password + nameHMAC + Util.generateRandomBase64Noise();

    // Encryption

    let AesGcmParams = {
      name: "AES-GCM",
      iv: iv,
    }

    let encryptedPasswordData = await subtle.encrypt(AesGcmParams, AES_KEY, passwordData);

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
    let AesGcmParams = {
      name: "AES-GCM",
      iv: iv,
    }

    let passwordData = await subtle.decrypt(AesGcmParams, AES_KEY, encryptedPasswordData);

    passwordData = Util.byteArrayToString(passwordData);
    // Password Data = Password + nameHMAC + Random Noise Padding
    return passwordData;
  }

  /* Dummy Data Generators ***********************************************************/

  static generateDummyDomain() {
    const characters = "abcdefghijklmnopqrstuvwxyz";
    let result = "";
    const charactersLength = characters.length;
    for (let i = 0; i < 7; i++) {
      result += characters.charAt(Math.floor(Math.random() * charactersLength));
    }
    result = result.substring(1, 8);
    // result = "www." + result + ".com";
    return result;
  }

  static generateDummyPassword() {
    const characters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*";
    let result = "";
    const charactersLength = characters.length;
    for (let i = 0; i < 8; i++) {
      result += characters.charAt(Math.floor(Math.random() * charactersLength));
    }
    result = result.substring(1, 9);
    return result;
  }
}

module.exports = Util;
