const html = require('html')
import * as striptags from 'striptags'

import {performanceTest} from './performanceTest';

(async () => {
  const results = await performanceTest();
  const prettyData = html.prettyPrint(results, {indent_size: 2});
  console.log(striptags(prettyData));
})().catch(console.error)
