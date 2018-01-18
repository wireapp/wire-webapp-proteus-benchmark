function performanceTest(Benchmark, sodium, onComplete) {
  const options = {minSamples: 50};
  let output = '';
  const times = [];

  const suite = new Benchmark.Suite;

  const aliceKeyPair = sodium.crypto_sign_keypair();
  const ed25519SecretKeyAlice = aliceKeyPair.privateKey;
  const curve25519SecretKeyAlice = sodium.crypto_sign_ed25519_sk_to_curve25519(ed25519SecretKeyAlice);

  const bobKeyPair = sodium.crypto_sign_keypair();
  const ed25519PublicKeyBob = bobKeyPair.publicKey;
  const curve25519PublicKeyBob = sodium.crypto_sign_ed25519_pk_to_curve25519(ed25519PublicKeyBob);

  let authenticator;
  const message = 'Hello';
  const salt = '000102030405060708090a0b0c';

  const keyMaterial = [5, 30, 208, 218, 140, 173, 89, 133, 238, 120, 243, 172, 56, 0, 84, 80, 225, 83, 110, 68, 59, 136, 105, 202, 200, 243, 73, 174, 28, 38, 66, 246];
  const keyMaterialBuffer = new ArrayBuffer(keyMaterial.length);
  const typedKeyMaterial = new Uint8Array(keyMaterialBuffer);

  const nonce = [0, 1, 2, 3, 4, 5, 6, 7];
  const nonceBuffer = new ArrayBuffer(nonce.length);
  const typedNonce = new Uint8Array(nonceBuffer);

  suite
    .add('sodium.crypto_auth_hmacsha256', () => {
      authenticator = sodium.crypto_auth_hmacsha256(message, typedKeyMaterial);
    }, options)
    .add('sodium.crypto_auth_hmacsha256_verify', () => {
      const isCorrectAuthenticator = sodium.crypto_auth_hmacsha256_verify(authenticator, message, typedKeyMaterial);
    }, options)
    .add('sodium.crypto_hash_sha256', () => {
      const hash = sodium.crypto_hash_sha256(salt);
    }, options)
    .add('sodium.crypto_scalarmult', () => {
      const sharedSecret = sodium.crypto_scalarmult(curve25519SecretKeyAlice, curve25519PublicKeyBob);
    }, options)
    .add('sodium.crypto_sign_detached', () => {
      const messageSignature = sodium.crypto_sign_detached(message, ed25519SecretKeyAlice);
    }, options)
    .add('sodium.crypto_sign_ed25519_pk_to_curve25519', () => {
      const curve25519_pk = sodium.crypto_sign_ed25519_pk_to_curve25519(ed25519PublicKeyBob);
    }, options)
    .add('sodium.crypto_sign_ed25519_sk_to_curve25519', () => {
      const curve25519_sk = sodium.crypto_sign_ed25519_sk_to_curve25519(ed25519SecretKeyAlice);
    }, options)
    .add('sodium.crypto_sign_keypair', () => {
      const keypair = sodium.crypto_sign_keypair();
    }, options)
    .add('sodium.crypto_stream_chacha20_xor', () => {
      const encryptedMessage = sodium.crypto_stream_chacha20_xor(message, typedNonce, typedKeyMaterial, 'uint8array');
    }, options)
    .on('cycle', event => {
      output += `${String(event.target)}<br/>`;
      times.push(event.target.hz);
    })
    .on('complete', () => {
      const average = times.reduce((x, y) => x + y) / times.length;
      output += `<br>Average: ${average.toLocaleString(undefined, {maximumFractionDigits: 0})} ops/sec`;
      onComplete(output);
    }).run({'async': true});
}

if (typeof window !== 'undefined') {
  window.performanceTest = performanceTest;
} else {
  module.exports = performanceTest;
}
