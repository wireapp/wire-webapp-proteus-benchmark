function performanceTest(Benchmark, sodium, onComplete) {
  var options = {minSamples: 50};
  var output = '';

  var suite = new Benchmark.Suite;

  var aliceKeyPair = sodium.crypto_sign_keypair();
  var ed25519SecretKeyAlice = aliceKeyPair.privateKey;
  var curve25519SecretKeyAlice = sodium.crypto_sign_ed25519_sk_to_curve25519(ed25519SecretKeyAlice);

  var bobKeyPair = sodium.crypto_sign_keypair();
  var ed25519PublicKeyBob = bobKeyPair.publicKey;
  var curve25519PublicKeyBob = sodium.crypto_sign_ed25519_pk_to_curve25519(ed25519PublicKeyBob);

  var authenticator;
  var message = 'Hello';
  var salt = '000102030405060708090a0b0c';

  var keyMaterial = [5, 30, 208, 218, 140, 173, 89, 133, 238, 120, 243, 172, 56, 0, 84, 80, 225, 83, 110, 68, 59, 136, 105, 202, 200, 243, 73, 174, 28, 38, 66, 246];
  var keyMaterialBuffer = new ArrayBuffer(keyMaterial.length);
  var typedKeyMaterial = new Uint8Array(keyMaterialBuffer);

  var nonce = [0, 1, 2, 3, 4, 5, 6, 7];
  var nonceBuffer = new ArrayBuffer(nonce.length);
  var typedNonce = new Uint8Array(nonceBuffer);

  suite
    .add('sodium.crypto_auth_hmacsha256', function() {
      authenticator = sodium.crypto_auth_hmacsha256(message, typedKeyMaterial);
    }, options)
    .add('sodium.crypto_auth_hmacsha256_verify', function() {
      var isCorrectAuthenticator = sodium.crypto_auth_hmacsha256_verify(authenticator, message, typedKeyMaterial);
    }, options)
    .add('sodium.crypto_hash_sha256', function() {
      var hash = sodium.crypto_hash_sha256(salt);
    }, options)
    .add('sodium.crypto_scalarmult', function() {
      var sharedSecret = sodium.crypto_scalarmult(curve25519SecretKeyAlice, curve25519PublicKeyBob);
    }, options)
    .add('sodium.crypto_sign_detached', function() {
      var messageSignature = sodium.crypto_sign_detached(message, ed25519SecretKeyAlice);
    }, options)
    .add('sodium.crypto_sign_ed25519_pk_to_curve25519', function() {
      var curve25519_pk = sodium.crypto_sign_ed25519_pk_to_curve25519(ed25519PublicKeyBob);
    }, options)
    .add('sodium.crypto_sign_ed25519_sk_to_curve25519', function() {
      var curve25519_sk = sodium.crypto_sign_ed25519_sk_to_curve25519(ed25519SecretKeyAlice);
    }, options)
    .add('sodium.crypto_sign_keypair', function() {
      var keypair = sodium.crypto_sign_keypair();
    }, options)
    .add('sodium.crypto_stream_chacha20_xor', function() {
      var encryptedMessage = sodium.crypto_stream_chacha20_xor(message, typedNonce, typedKeyMaterial, 'uint8array');
    }, options)
    .on('cycle', function(event) {
      output += String(event.target) + '<br/>';
    })
    .on('complete', function() {
      onComplete(output);
    }).run({'async': true});
}

if (typeof window !== 'undefined') {
  window.performanceTest = performanceTest;
} else {
  module.exports = performanceTest;
}
