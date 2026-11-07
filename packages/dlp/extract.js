'use strict';
// `@email-gateway/dlp/extract` for `moduleResolution: node10` (package `exports` subpaths are
// not resolved by tsc): re-exports the extractor entry point of the build.
module.exports = require('./dist/extract');
