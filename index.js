const Benchmark = require('benchmark');
const sodium = require('libsodium-wrappers-sumo');

const html = require('html');
const striptags = require('striptags');

const onComplete = output => {
  const prettyData = html.prettyPrint(output, {indent_size: 2});
  process.stdout.write(striptags(prettyData));
};

require('./performanceTest')(Benchmark, sodium, onComplete);
