"use strict";

/********* External Imports ********/

const { randomInt, subtle } = require("crypto");
const Util = require("./lib");

/********* Implementation ********/

const PBKDF2_ITERATIONS = 100000;

class Keychain {
  /**
   * Initializes the keychain using the provided information. Note that external
   * users should likely never invoke the constructor directly and instead use
   * either Keychain.init or Keychain.load.
   * Arguments:
   * You may design the constructor with any parameters you would like.
   * Return Type: void
   */
  constructor(salt, iterations, HMAC_KEY, AES_KEY, HMAC_KEY_DERIVATION_SALT, AES_KEY_DERIVATION_SALT) {
    this.data = {
      /* Store member variables that you intend to be public here
         (i.e. informationUtil that will not compromise security if an adversary sees) */
      version: "CSEDU Password Manager v1.0",
      kvs: {},
      salt: salt,
      iterations: iterations,
      HMAC_KEY_DERIVATION_SALT: HMAC_KEY_DERIVATION_SALT,
      AES_KEY_DERIVATION_SALT: AES_KEY_DERIVATION_SALT,
    };

    this.secrets = {
      /* Store member variables that you intend to be private here
         (information that an adversary should NOT see). */
      HMAC_KEY: HMAC_KEY,
      AES_KEY: AES_KEY,
    };

    this.ready = true;
  }

  readyCheck() {
    if (!this.ready) {
      throw "Keychain not initialized.";
    }
  }

  /**
   * Creates an empty keychain with the given password. Once the constructor
   * has finished, the password manager should be in a ready state.
   *
   * Arguments:
   *   password: string
   * Return Type: KeyChain
   */
  static async init(password) {
    // Master Key Generation
    let salt = Util.generateRandomSalt();
    let iterations = PBKDF2_ITERATIONS;
    let masterKey = null;

    [salt, masterKey] = await Util.generateMasterKey(password, salt, iterations);

    // HMAC Key Generation
    let HMAC_KEY_DERIVATION_SALT = Util.generateRandomSalt(32);
    let HMAC_KEY = await Util.generateHMACKey(masterKey, HMAC_KEY_DERIVATION_SALT);

    // AES Key Generation
    let AES_KEY_DERIVATION_SALT = Util.generateRandomSalt(32);
    let AES_KEY = await Util.generateAESKey(masterKey, AES_KEY_DERIVATION_SALT);

    // Password Manager Init
    let passwordManager = new Keychain(salt, iterations, HMAC_KEY, AES_KEY, HMAC_KEY_DERIVATION_SALT, AES_KEY_DERIVATION_SALT);
    return passwordManager;
  }

  /**
   * Loads the keychain state from the provided representation (repr). The
   * repr variable will contain a JSON encoded serialization of the contents
   * of the KVS (as returned by the dump function). The trustedDataCheck
   * is an *optional* SHA-256 checksum that can be used to validate the
   * integrity of the contents of the KVS. If the checksum is provided and the
   * integrity check fails, an exception should be thrown. You can assume that
   * the representation passed to load is well-formed (i.e., it will be
   * a valid JSON object).Returns a Keychain object that contains the data
   * from repr.
   *
   * Arguments:
   *   password:           string
   *   repr:               string
   *   trustedDataCheck: string
   * Return Type: Keychain
   */
  static async load(password, repr, trustedDataCheck) {
    // Validate Checksum: handles rollback attack
    if (trustedDataCheck !== undefined) {
      // SHA-256 Checksum
      let checksum = await subtle.digest("SHA-256", repr);
      checksum = Util.arrayBufferToBase64(checksum);
      if (checksum !== trustedDataCheck) {
        throw "[CHECKSUM FAILURE] Data has been tampered with!";
      }
    }

    // Parse JSON
    let keychain = JSON.parse(repr);

    // Check for salt in repr
    if (!("salt" in keychain) || keychain["salt"] == undefined) {
      throw "salt not found in repr!";
    }

    // Check for iterations in repr
    if (!("iterations" in keychain) || keychain["iterations"] == undefined) {
      throw "iterations not found in repr!";
    }

    // Regenerate Master Key from Password
    let salt = keychain["salt"];
    let iterations = keychain["iterations"];
    let masterKey = null;

    [salt, masterKey] = await Util.generateMasterKey(password, salt, iterations);

    // Regenerate HMAC Key from Master Key
    const HMAC_KEY_DERIVATION_SALT = keychain["HMAC_KEY_DERIVATION_SALT"];
    let HMAC_KEY = await Util.generateHMACKey(masterKey, HMAC_KEY_DERIVATION_SALT);
    
    // Regenerate AES Key from Master Key
    const AES_KEY_DERIVATION_SALT = keychain["AES_KEY_DERIVATION_SALT"];
    let AES_KEY = await Util.generateAESKey(masterKey, AES_KEY_DERIVATION_SALT);

    // New Password Manager with Old Data
    this.passwordManager = new Keychain(salt, iterations, HMAC_KEY, AES_KEY, HMAC_KEY_DERIVATION_SALT, AES_KEY_DERIVATION_SALT);
    this.passwordManager.data = keychain;
    return this.passwordManager;
  }

  /**
   * Returns a JSON serialization of the contents of the keychain that can be
   * loaded back using the load function. The return value should consist of
   * an array of two strings:
   *   arr[0] = JSON encoding of password manager
   *   arr[1] = SHA-256 checksum (as a string)
   * As discussed in the handout, the first element of the array should contain
   * all of the data in the password manager. The second element is a SHA-256
   * checksum computed over the password manager to preserve integrity. If the
   * password manager is not in a ready-state, return null.
   *
   * Return Type: array
   */
  async dump() {
    if (!this.ready) {
      return null;
    }

    // Serialization of keychain data
    let repr = JSON.stringify(this.data);

    // SHA-256 Checksum
    let trustedDataCheck = await subtle.digest("SHA-256", repr);
    trustedDataCheck = Util.arrayBufferToBase64(trustedDataCheck);

    return [repr, trustedDataCheck];
  }

  /**
   * Fetches the data (as a string) corresponding to the given domain from the KVS.
   * If there is no entry in the KVS that matches the given domain, then return
   * null. If the password manager is not in a ready state, throw an exception. If
   * tampering has been detected with the records, throw an exception.
   *
   * Arguments:
   *   name: string
   * Return Type: Promise<string>
   */
  async get(name) {
    this.readyCheck();

    let password = null;

    // HMAC of domain name (Base64)
    let nameHMAC = await Util.HMAC(this.secrets.HMAC_KEY, name);

    // If Exists in KVS
    if (this.data.kvs[nameHMAC] !== undefined) {
      // Decrypt
      let passwordData = await Util.decryptPassword(this.data.kvs[nameHMAC], this.secrets.AES_KEY);
      // Handles Swap Attack
      var nameHMACIndex = passwordData.indexOf(nameHMAC);
      if (nameHMACIndex == -1) {
        throw "[SWAP ATTACK DETECTED]";
      }
      password = passwordData.substring(0, nameHMACIndex);
    }

    return password;
  }

  /**
   * Inserts the domain and associated data into the KVS. If the domain is
   * already in the password manager, this method should update its value. If
   * not, create a new entry in the password manager. If the password manager is
   * not in a ready state, throw an exception.
   *
   * Arguments:
   *   name: string
   *   value: string
   * Return Type: void
   */
  async set(name, value) {
    this.readyCheck();

    // HMAC of domain name (Base64)
    let nameHMAC = await Util.HMAC(this.secrets.HMAC_KEY, name);

    // Encrypted Password Data = IV (Base64) + Encrypt (Password + nameHMAC + Random Noise Padding)
    let encryptedPasswordData = await Util.encryptPassword(nameHMAC, value, this.secrets.AES_KEY);

    // Set
    this.data.kvs[nameHMAC] = encryptedPasswordData;

    // Dummy Record Set
    let chance = randomInt(10);
    if (chance == 0 || chance == 9) {
      await this.set(Util.generateDummyDomain(), Util.generateDummyPassword());
      await this.set(Util.generateDummyDomain(), Util.generateDummyPassword());
    } 
    else if (chance>1 && chance<5) {
      await this.set(Util.generateDummyDomain(), Util.generateDummyPassword());
    }
  }

  /**
   * Removes the record with name from the password manager. Returns true
   * if the record with the specified name is removed, false otherwise. If
   * the password manager is not in a ready state, throws an exception.
   *
   * Arguments:
   *   name: string
   * Return Type: Promise<boolean>
   */
  async remove(name) {
    this.readyCheck();

    // HMAC of domain name (Base64)
    let nameHMAC = await Util.HMAC(this.secrets.HMAC_KEY, name);

    // Check if it exists in the KVS
    if (this.data.kvs[nameHMAC] !== undefined) {
      // Remove
      delete this.data.kvs[nameHMAC];
      return true;
    }

    return false;
  }
}

module.exports = {
  Keychain: Keychain,
};
