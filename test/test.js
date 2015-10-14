'use strict';

var _ = require('underscore');
var assert = require('assert');
var crypto = require('crypto');
var fs = require('fs');
var sinon = require('sinon');
var request = require('request');
var verifier = require('../lib/main');
var testEnvelope = require('./fixtures/envelope');
var testToken = require('./fixtures/idToken');
var testOAuthCerts = require('./fixtures/oauthcerts');

describe('verifying google idToken', function () {
  before(function (done) {
    sinon
      .stub(request, 'get')
      .yields(null, { statusCode: 200, headers: {} }, testOAuthCerts);
    done();
  });

  after(function (done) {
    request.get.restore();
    done();
  });

  it('should succeed to get tokenInfo with verifying', function (done) {
    var privateKey = fs.readFileSync('./test/fixtures/private.pem', 'utf-8');

    var maxLifetimeSecs = 86400;
    var now = new Date().getTime() / 1000;
    var expiry = now + (maxLifetimeSecs / 2);

    var payload = _.clone(testToken);
    payload.iat = now;
    payload.exp = expiry;

    var envelope = _.clone(testEnvelope);

    var data = new Buffer(JSON.stringify(envelope)).toString('base64') +
      '.' + new Buffer(JSON.stringify(payload)).toString('base64');

    var signer = crypto.createSign('sha256');
    signer.update(data);
    var signature = signer.sign(privateKey, 'base64');

    data += '.' + signature;

    verifier.verify(data, payload.aud, function (error, tokenInfo) {
      assert.equal(_.isEmpty(error), true);
      assert.equal(request.get.called, true);
      assert.equal(tokenInfo.sub, payload.sub);
      done();
    });
  });
});
