var Benchmark = require('benchmark');
var html = require('html');
var sodium = require('libsodium');
var striptags = require('striptags');

var onComplete = function(output) {
  var prettyData = html.prettyPrint(output, {indent_size: 2});
  process.stdout.write(striptags(prettyData));
};

require('./performanceTest')(Benchmark, sodium, onComplete);
