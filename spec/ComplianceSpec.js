const chacha20 = require('chacha20');
const ed2curve = require('ed2curve');
const sodium = require('libsodium-wrappers-sumo');

describe('ComplianceSpec', () => {
  describe('ChaCha20', () => {
    describe("crypto_stream_chacha20_xor", () => {
      it("proves that sodium's ChaCha20 function is compatible to the chacha20 lib.", () => {
        const plainText = 'Hello';
        
        let nonce = [0, 1, 2, 3, 4, 5, 6, 7];
        const nonceBuffer = new ArrayBuffer(nonce.length);
        const typedNonce = new Uint8Array(nonceBuffer);
        
        const keyMaterial = [5, 30, 208, 218, 140, 173, 89, 133, 238, 120, 243, 172, 56, 0, 84, 80, 225, 83, 110, 68, 59, 136, 105, 202, 200, 243, 73, 174, 28, 38, 66, 246];
        const keyMaterialBuffer = new ArrayBuffer(keyMaterial.length);
        const typedKeyMaterial = new Uint8Array(keyMaterialBuffer);
        
        let cipherText = sodium.crypto_stream_chacha20_xor(plainText, typedNonce, typedKeyMaterial, 'uint8array');
        let cipherTextInHex = sodium.to_hex(cipherText);
        
        expect(cipherTextInHex).toBe('3edd8cc1cf');
        
        const key = typedKeyMaterial.buffer;
        nonce = typedNonce.buffer;
        
        cipherText = chacha20.encrypt(key, nonce, new Buffer(plainText));
        cipherTextInHex = cipherText.toString('hex');
        expect(cipherTextInHex).toBe('3edd8cc1cf');
        
        const decrypted = chacha20.decrypt(key, nonce, cipherText).toString();
        expect(decrypted).toBe(plainText);
      });
    });
  });
  
  describe('Ed25519', () => {
    const alice = {
      keyPair: {
        privateKey: {
          ed25519: undefined,
          curve25519: undefined
        },
        publicKey: {
          ed25519: undefined,
          curve25519: undefined
        }
      }
    };
    
    beforeAll(() => {
      const aliceKeyPair = sodium.crypto_sign_keypair();
      
      alice.keyPair.privateKey.ed25519 = aliceKeyPair.privateKey;
      alice.keyPair.privateKey.curve25519 = sodium.crypto_sign_ed25519_sk_to_curve25519(aliceKeyPair.privateKey);
      
      alice.keyPair.publicKey.ed25519 = aliceKeyPair.publicKey;
      alice.keyPair.publicKey.curve25519 = sodium.crypto_sign_ed25519_pk_to_curve25519(aliceKeyPair.publicKey);
    });
    
    describe("crypto_sign_ed25519_pk_to_curve25519", () => {
      it("converts an Ed25519 public key to a Curve25519 public key", () => {
        const curve25519WithSodium = sodium.crypto_sign_ed25519_pk_to_curve25519(alice.keyPair.publicKey.ed25519);
        const curve25519WithTweetNaCl = ed2curve.convertPublicKey(alice.keyPair.publicKey.ed25519);
        
        expect(curve25519WithSodium).toBeDefined();
        expect(curve25519WithTweetNaCl).toEqual(curve25519WithSodium);
      });
    });
    
    describe("crypto_sign_ed25519_sk_to_curve25519", () => {
      it("converts an Ed25519 secret key to a Curve25519 secret key", () => {
        const curve25519WithSodium = sodium.crypto_sign_ed25519_sk_to_curve25519(alice.keyPair.privateKey.ed25519);
        const curve25519WithTweetNaCl = ed2curve.convertSecretKey(alice.keyPair.privateKey.ed25519);
        
        expect(curve25519WithSodium).toBeDefined();
        expect(curve25519WithTweetNaCl).toEqual(curve25519WithSodium);
      });
    });
  });
});
