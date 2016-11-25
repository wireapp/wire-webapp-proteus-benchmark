var ed2curve = require('ed2curve');
var sodium = require('libsodium');

describe('ComplianceSpec', function() {
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

  beforeAll(function() {
    var aliceKeyPair = sodium.crypto_sign_keypair();

    alice.keyPair.privateKey.ed25519 = aliceKeyPair.privateKey;
    alice.keyPair.privateKey.curve25519 = sodium.crypto_sign_ed25519_sk_to_curve25519(aliceKeyPair.privateKey);

    alice.keyPair.publicKey.ed25519 = aliceKeyPair.publicKey;
    alice.keyPair.publicKey.curve25519 = sodium.crypto_sign_ed25519_pk_to_curve25519(aliceKeyPair.publicKey);
  });

  describe("crypto_sign_ed25519_pk_to_curve25519", function() {
    it("converts an Ed25519 public key to a Curve25519 public key", function() {
      var curve25519WithSodium = sodium.crypto_sign_ed25519_pk_to_curve25519(alice.keyPair.publicKey.ed25519);
      var curve25519WithTweetNaCl = ed2curve.convertPublicKey(alice.keyPair.publicKey.ed25519);

      expect(curve25519WithSodium).toBeDefined();
      expect(curve25519WithTweetNaCl).toEqual(curve25519WithSodium);
    });
  });

  describe("crypto_sign_ed25519_sk_to_curve25519", function() {
    it("converts an Ed25519 secret key to a Curve25519 secret key", function() {
      var curve25519WithSodium = sodium.crypto_sign_ed25519_sk_to_curve25519(alice.keyPair.privateKey.ed25519);
      var curve25519WithTweetNaCl = ed2curve.convertSecretKey(alice.keyPair.privateKey.ed25519);

      expect(curve25519WithSodium).toBeDefined();
      expect(curve25519WithTweetNaCl).toEqual(curve25519WithSodium);
    });
  });
});
