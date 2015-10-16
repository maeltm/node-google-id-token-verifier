# node-google-id-token-verifier

[![Build Status](https://travis-ci.org/maeltm/node-google-id-token-verifier.svg?branch=master)](https://travis-ci.org/maeltm/node-google-id-token-verifier)

This is library to validate a google ID token for consuming it in [node.js][node] backend server.
This is very similar to google's [tokeninfo endpoint][tokeninfo].

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

[node]: http://nodejs.org/
[tokeninfo]: https://www.googleapis.com/oauth2/v3/tokeninfo
