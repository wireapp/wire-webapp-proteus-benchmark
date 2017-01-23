var chacha20 = require("chacha20");
var ed2curve = require('ed2curve');
var sodium = require('libsodium');

describe('ComplianceSpec', function () {

  describe('ChaCha20', function () {
    describe("crypto_stream_chacha20_xor", function () {
      it("proves that sodium's ChaCha20 function is compatible to the chacha20 lib.", function () {
        // require('libsodium')
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

        // require("chacha20")
        var key = typedKeyMaterial.buffer;
        var nonce = typedNonce.buffer;
        cipherText = chacha20.encrypt(key, nonce, new Buffer(plainText));
        cipherTextInHex = cipherText.toString('hex');

        expect(cipherTextInHex).toBe('3edd8cc1cf');

        var decrypted = chacha20.decrypt(key, nonce, cipherText).toString();

        expect(decrypted).toBe(plainText);
      });

      it("shows that multiple implementations follow the RFC test vectors from https://tools.ietf.org/html/draft-agl-tls-chacha20poly1305-04#section-7", function () {
        var vectors = [
          {
            key: '0000000000000000000000000000000000000000000000000000000000000000',
            nonce: '0000000000000000',
            keyStream: '76b8e0ada0f13d90405d6ae55386bd28bdd219b8a08ded1aa836efcc8b770dc7da41597c5157488d7724e03fb8d84a376a43b8f41518a11cc387b669b2ee6586'
          },
          {
            key: '0000000000000000000000000000000000000000000000000000000000000001',
            nonce: '0000000000000000',
            keyStream: '4540f05a9f1fb296d7736e7b208e3c96eb4fe1834688d2604f450952ed432d41bbe2a0b6ea7566d2a5d1e7e20d42af2c53d792b1c43fea817e9ad275ae546963'
          },
          {
            key: '0000000000000000000000000000000000000000000000000000000000000000',
            nonce: '0000000000000001',
            keyStream: 'de9cba7bf3d69ef5e786dc63973f653a0b49e015adbff7134fcb7df137821031e85a050278a7084527214f73efc7fa5b5277062eb7a0433e445f41e3'
          },
          {
            key: '0000000000000000000000000000000000000000000000000000000000000000',
            nonce: '0100000000000000',
            keyStream: 'ef3fdfd6c61578fbf5cf35bd3dd33b8009631634d21e42ac33960bd138e50d32111e4caf237ee53ca8ad6426194a88545ddc497a0b466e7d6bbdb0041b2f586b'
          }
        ];

        for (var i = 0; i < vectors.length; i++) {
          var vector = vectors[i];

          var key = sodium.from_hex(vector.key);
          var nonce = sodium.from_hex(vector.nonce);
          var keyStream = vector.keyStream;

          var message = new Uint8Array(keyStream.length >> 1);
          var result = sodium.crypto_stream_chacha20_xor(message, nonce, key, 'hex');
          expect(result).toBe(keyStream);
        }
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
