#!/usr/bin/env node
// Run the browser engine (static/analyzer.js) under Node - used by the JS/Python parity test.
//   node tools/js_analyze.js <iam-export.json> [ISO-now]
'use strict';
const fs = require('fs');
const path = require('path');

const root = path.resolve(__dirname, '..');
require(path.join(root, 'static', 'catalog.js'));
const engine = require(path.join(root, 'static', 'analyzer.js'));

const [file, now] = process.argv.slice(2);
if (!file) { console.error('usage: node tools/js_analyze.js <file.json> [ISO-now]'); process.exit(2); }
try {
  const data = JSON.parse(fs.readFileSync(file, 'utf-8').replace(/^﻿/, ''));
  const result = engine.analyze(data, { source: path.basename(file), now: now || undefined });
  process.stdout.write(JSON.stringify(result));
} catch (e) {
  console.error(`${e.name}: ${e.message}`);
  process.exit(2);
}
