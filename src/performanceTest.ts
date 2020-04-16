import * as Benchmark from 'benchmark';
import * as sodium from 'libsodium-wrappers-sumo';

export async function performanceTest(): Promise<string> {
  await sodium.ready;
  const options = {minSamples: 50};
  let output = '';
  const times: number[] = [];

  const suite = new Benchmark.Suite;

  const aliceKeyPair = sodium.crypto_sign_keypair();
  const ed25519SecretKeyAlice = aliceKeyPair.privateKey;
  const curve25519SecretKeyAlice = sodium.crypto_sign_ed25519_sk_to_curve25519(ed25519SecretKeyAlice);

  const bobKeyPair = sodium.crypto_sign_keypair();
  const ed25519PublicKeyBob = bobKeyPair.publicKey;
  const curve25519PublicKeyBob = sodium.crypto_sign_ed25519_pk_to_curve25519(ed25519PublicKeyBob);

  let authenticator: Uint8Array;
  const message = 'Hello';
  const salt = '000102030405060708090a0b0c';

  const keyMaterial = [5, 30, 208, 218, 140, 173, 89, 133, 238, 120, 243, 172, 56, 0, 84, 80, 225, 83, 110, 68, 59, 136, 105, 202, 200, 243, 73, 174, 28, 38, 66, 246];
  const keyMaterialBuffer = new ArrayBuffer(keyMaterial.length);
  const typedKeyMaterial = new Uint8Array(keyMaterialBuffer);

  const nonce = [0, 1, 2, 3, 4, 5, 6, 7];
  const nonceBuffer = new ArrayBuffer(nonce.length);
  const typedNonce = new Uint8Array(nonceBuffer);

  return await new Promise(resolve => {
  suite
    .add('sodium.crypto_auth_hmacsha256', () => {
      authenticator = sodium.crypto_auth_hmacsha256(message, typedKeyMaterial);
    }, options)
    .add('sodium.crypto_auth_hmacsha256_verify', () => {
      sodium.crypto_auth_hmacsha256_verify(authenticator, message, typedKeyMaterial);
    }, options)
    .add('sodium.crypto_hash_sha256', () => sodium.crypto_hash_sha256(salt), options)
    .add('sodium.crypto_scalarmult', () => {
      sodium.crypto_scalarmult(curve25519SecretKeyAlice, curve25519PublicKeyBob);
    }, options)
    .add('sodium.crypto_sign_detached', () => {
      sodium.crypto_sign_detached(message, ed25519SecretKeyAlice);
    }, options)
    .add('sodium.crypto_sign_ed25519_pk_to_curve25519', () => {
      sodium.crypto_sign_ed25519_pk_to_curve25519(ed25519PublicKeyBob);
    }, options)
    .add('sodium.crypto_sign_ed25519_sk_to_curve25519', () => {
      sodium.crypto_sign_ed25519_sk_to_curve25519(ed25519SecretKeyAlice);
    }, options)
    .add('sodium.crypto_sign_keypair', () => {
      sodium.crypto_sign_keypair();
    }, options)
    .add('sodium.crypto_stream_chacha20_xor', () => sodium.crypto_stream_chacha20_xor(message, typedNonce, typedKeyMaterial, 'uint8array'), options)
    .on('cycle', (event: any) => {
      output += `${String(event.target)}<br/>`;
      times.push(event.target.hz);
    })
    .on('complete', () => {
      const average = times.reduce((x, y) => x + y) / times.length;
      output += `<br>Average: ${average.toLocaleString(undefined, {maximumFractionDigits: 0})} ops/sec`;
      resolve(output);
    }).run({'async': true});
  });
}
