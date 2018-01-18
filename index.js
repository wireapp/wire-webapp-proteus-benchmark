const Benchmark = require('benchmark');
const _sodium = require('libsodium-wrappers-sumo');

const html = require('html');
const striptags = require('striptags');

const onComplete = output => {
  const prettyData = html.prettyPrint(output, {indent_size: 2});
  process.stdout.write(striptags(prettyData));
};

async function start() {
  await _sodium.ready;
  const sodium = _sodium;
  require('./performanceTest')(Benchmark, sodium, onComplete);
}

start();
