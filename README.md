# google-id-token-verifier

[![Build Status][travisimg]][travis]
[![Coverage Status][coverallsimg]][coveralls]

This is library to validate a google ID token for consuming it in [node.js][node] backend server.
This is very similar to google's [tokeninfo endpoint][tokeninfo].

## Installation

```bash
npm install google-id-token-verifier --save
```

## Usage

```js
var verifier = require('google-id-token-verifier');

// ID token from client.
var IdToken = 'XYZ123';

// app's client IDs to check with audience in ID Token.
var clientId = 'abc123.apps.googleusercontent.com';

verifier.verify(IdToken, clientId, function (err, tokenInfo) {
  if (!err) {
    // use tokenInfo in here.
    console.log(tokenInfo);
  }
});
```

## Tests

```bash
npm test
```
or
```bash
npm prepare
```

## Contributing

In lieu of a formal styleguide, take care to maintain the existing coding style.
Add unit tests for any new or changed functionality. Lint and test your code.

## Third-party libraries

The following third-party libraries are used by this module:

* request: https://github.com/request/request - to get google's oauth2 federated signon certs.

## Inspired by

* google-auth-library-nodejs - https://github.com/google/google-auth-library-nodejs
* google-id-token - https://github.com/gmelika/google-id-token

## Release History

* 0.1.0 Initial release

[travisimg]: https://travis-ci.org/maeltm/node-google-id-token-verifier.svg?branch=master
[travis]: https://travis-ci.org/maeltm/node-google-id-token-verifier
[coverallsimg]: https://coveralls.io/repos/maeltm/node-google-id-token-verifier/badge.svg?branch=master&service=github
[coveralls]: https://coveralls.io/github/maeltm/node-google-id-token-verifier?branch=master
[node]: http://nodejs.org/
[tokeninfo]: https://www.googleapis.com/oauth2/v3/tokeninfo
