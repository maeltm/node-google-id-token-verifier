'use strict';

var _ = require('underscore');
var certCache = require('./certCache');
var crypto = require('crypto');
var getPem = require('rsa-pem-from-mod-exp');

function decodeBase64WithUriEncoding(encodedText) {
  return new Buffer(encodedText, 'base64').toString('utf8');
}

function unescapedString(escapedString) {
  escapedString += new Array(5 - escapedString.length % 4).join('=');
  return escapedString.replace(/\-/g, '+').replace(/_/g, '/');
}

function decodeJWT(idToken) {
  var token = idToken.split('.');
  if (token.length !== 3) {
    throw new Error('Invalid idToken');
  }

  try {
    var headerSegment = JSON.parse(decodeBase64WithUriEncoding(token[0]));
    var payloadSegment = JSON.parse(decodeBase64WithUriEncoding(token[1]));
    var signature = unescapedString(token[2]);
    return {
      dataToSign: [token[0], token[1]].join('.'),
        header: headerSegment,
        payload: payloadSegment,
        signature: signature
    };
  } catch (e) {
    throw new Error('Invalid payload');
  }
}

function verifySignature(jwt, keys) {
  var kid = jwt.header.kid;
  if (_.isUndefined(kid) || !_.contains(_.pluck(keys, 'kid'), kid)) {
    throw new Error('Cannot not found valid JWK');
  }

  var key = _.findWhere(keys, {kid: kid});
  var pem = getPem(key.n, key.e);

  var verifier = crypto.createVerify('sha256');
  verifier.update(jwt.dataToSign);
  if (!verifier.verify(pem, jwt.signature, 'base64')) {
    throw new Error('Invalid Signature');
  }
}

function verifyPayload(payload, audience) {
  var now = new Date();

  if (!_.contains(['accounts.google.com', 'https://accounts.google.com'], payload.iss)) {
    throw new Error('Invalid idToken issuer');
  }

  if (payload.aud !== audience) {
    throw new Error('Invalid idToken audience');
  }

  if (now > new Date(payload.exp * 1000)) {
    throw new Error('Expired idToken');
  }
}

exports.verify = function (idToken, audience, callback) {
  certCache.global.getFederatedGoogleCerts(function (err, keys) {
    try {
      var decodedJWT = decodeJWT(idToken);
      verifySignature(decodedJWT, keys.keys);
      verifyPayload(decodedJWT.payload, audience);

      callback(null, decodedJWT.payload);
    } catch (e) {
      callback(e, null);
    }
  });
};
