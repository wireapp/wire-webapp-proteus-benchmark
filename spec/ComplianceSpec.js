var chacha20 = require("chacha20");
var ed2curve = require('ed2curve');
var sodium = require('libsodium');

describe('ComplianceSpec', function () {

  describe('ChaCha20', function () {
    describe("crypto_stream_chacha20_xor", function () {
      it("proves that sodium's ChaCha20 function is compatible to the chacha20 lib.", function () {
        // sodium
        var plainText = 'Hello';

        var nonce = [0, 1, 2, 3, 4, 5, 6, 7];
        var nonceBuffer = new ArrayBuffer(nonce.length);
        var typedNonce = new Uint8Array(nonceBuffer);

        var keyMaterial = [5, 30, 208, 218, 140, 173, 89, 133, 238, 120, 243, 172, 56, 0, 84, 80, 225, 83, 110, 68, 59, 136, 105, 202, 200, 243, 73, 174, 28, 38, 66, 246];
        var keyMaterialBuffer = new ArrayBuffer(keyMaterial.length);
        var typedKeyMaterial = new Uint8Array(keyMaterialBuffer);

        var cipherText = sodium.crypto_stream_chacha20_xor(plainText, typedNonce, typedKeyMaterial, 'uint8array');
        var cipherTextInHex = sodium.to_hex(cipherText);

        expect(cipherTextInHex).toBe('3edd8cc1cf');

        // chacha20
        var key = typedKeyMaterial.buffer;
        var nonce = typedNonce.buffer;
        cipherText = chacha20.encrypt(key, nonce, new Buffer(plainText));
        cipherTextInHex = cipherText.toString('hex');

        expect(cipherTextInHex).toBe('3edd8cc1cf');

        var decrypted = chacha20.decrypt(key, nonce, cipherText).toString();

        expect(decrypted).toBe(plainText);
      });

      xit("shows that multiple implementations follow the RFC test vectors from https://tools.ietf.org/html/draft-agl-tls-chacha20poly1305-04#section-7", function () {

      });
    });
  });

  describe('Ed25519', function () {
    var alice = {
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

    beforeAll(function () {
      var aliceKeyPair = sodium.crypto_sign_keypair();

      alice.keyPair.privateKey.ed25519 = aliceKeyPair.privateKey;
      alice.keyPair.privateKey.curve25519 = sodium.crypto_sign_ed25519_sk_to_curve25519(aliceKeyPair.privateKey);

      alice.keyPair.publicKey.ed25519 = aliceKeyPair.publicKey;
      alice.keyPair.publicKey.curve25519 = sodium.crypto_sign_ed25519_pk_to_curve25519(aliceKeyPair.publicKey);
    });

    describe("crypto_sign_ed25519_pk_to_curve25519", function () {
      it("converts an Ed25519 public key to a Curve25519 public key", function () {
        var curve25519WithSodium = sodium.crypto_sign_ed25519_pk_to_curve25519(alice.keyPair.publicKey.ed25519);
        var curve25519WithTweetNaCl = ed2curve.convertPublicKey(alice.keyPair.publicKey.ed25519);

        expect(curve25519WithSodium).toBeDefined();
        expect(curve25519WithTweetNaCl).toEqual(curve25519WithSodium);
      });
    });

    describe("crypto_sign_ed25519_sk_to_curve25519", function () {
      it("converts an Ed25519 secret key to a Curve25519 secret key", function () {
        var curve25519WithSodium = sodium.crypto_sign_ed25519_sk_to_curve25519(alice.keyPair.privateKey.ed25519);
        var curve25519WithTweetNaCl = ed2curve.convertSecretKey(alice.keyPair.privateKey.ed25519);

        expect(curve25519WithSodium).toBeDefined();
        expect(curve25519WithTweetNaCl).toEqual(curve25519WithSodium);
      });
    });
  });

});
