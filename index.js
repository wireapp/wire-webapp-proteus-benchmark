var Benchmark = require('benchmark');
var sodium = require('libsodium-wrappers-sumo');

var html = require('html');
var striptags = require('striptags');

var onComplete = function(output) {
  var prettyData = html.prettyPrint(output, {indent_size: 2});
  process.stdout.write(striptags(prettyData));
};

require('./performanceTest')(Benchmark, sodium, onComplete);
