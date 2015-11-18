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

function makeFakeIdToken(payload, envelope) {
  var privateKey = fs.readFileSync('./test/fixtures/private.pem', 'utf-8');

  var data = new Buffer(JSON.stringify(envelope)).toString('base64') +
    '.' + new Buffer(JSON.stringify(payload)).toString('base64');

  var signer = crypto.createSign('sha256');
  signer.update(data);
  var signature = signer.sign(privateKey, 'base64');

  data += '.' + signature;

  return data;
}

function makeValidPayload(payload) {
  var maxLifetimeSecs = 86400;
  var now = new Date().getTime() / 1000;
  var expiry = now + (maxLifetimeSecs / 2);

  payload.iat = now;
  payload.exp = expiry;

  return payload;
}

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
    var payload = makeValidPayload(_.clone(testToken));
    var envelope = _.clone(testEnvelope);
    var data = makeFakeIdToken(payload, envelope);

    verifier.verify(data, payload.aud, function (error, tokenInfo) {
      assert.equal(_.isError(error), false);
      assert.equal(tokenInfo.sub, payload.sub);
      done();
    });
  });

  it('should fail to load payload if iss is invalid', function (done) {
    var payload = makeValidPayload(_.clone(testToken));
    payload.iss = 'invalid.issuer.domain';
    var envelope = _.clone(testEnvelope);
    var data = makeFakeIdToken(payload, envelope);

    verifier.verify(data, payload.aud, function (error, tokenInfo) {
      assert.equal(_.isError(error), true);
      assert.equal(error.message, 'Invalid idToken issuer');
      assert.equal(_.isEmpty(tokenInfo), true);
      done();
    });
  });

  it('should fail to verify signature if jwk is invalid', function (done) {
    var payload = makeValidPayload(_.clone(testToken));
    var envelope = _.clone(testEnvelope);
    envelope.kid = 'invalidKid';
    var data = makeFakeIdToken(payload, envelope);

    verifier.verify(data, payload.aud, function (error, tokenInfo) {
      assert.equal(_.isError(error), true);
      assert.equal(error.message, 'Cannot not found valid JWK');
      assert.equal(_.isEmpty(tokenInfo), true);
      done();
    });
  });

  it('should fail to decode JWT if idToken is invalid', function (done) {
    var payload = makeValidPayload(_.clone(testToken));
    var envelope = _.clone(testEnvelope);
    var data = makeFakeIdToken(payload, envelope);
    data += '.invalidCode';

    verifier.verify(data, payload.aud, function (error, tokenInfo) {
      assert.equal(_.isError(error), true);
      assert.equal(error.message, 'Invalid idToken');
      assert.equal(_.isEmpty(tokenInfo), true);
      done();
    });
  });

  it('should fail to decode JWT if payload is invalid', function (done) {
    var payload = makeValidPayload(_.clone(testToken));
    var envelope = _.clone(testEnvelope);

    var privateKey = fs.readFileSync('./test/fixtures/private.pem', 'utf-8');

    var data = new Buffer(JSON.stringify(envelope)).toString('base64') +
      '.' + new Buffer(JSON.stringify(payload) + 'invalidJson').toString('base64');

    var signer = crypto.createSign('sha256');
    signer.update(data);
    var signature = signer.sign(privateKey, 'base64');

    data += '.' + signature;

    verifier.verify(data, payload.aud, function (error, tokenInfo) {
      assert.equal(_.isError(error), true);
      assert.equal(error.message, 'Invalid payload');
      assert.equal(_.isEmpty(tokenInfo), true);
      done();
    });
  });

  it('should fail to verify signature if signature is invalid', function (done) {
    var payload = makeValidPayload(_.clone(testToken));
    var envelope = _.clone(testEnvelope);
    var data = makeFakeIdToken(payload, envelope);
    var invalidSignatureData = data.substring(0, data.lastIndexOf('.') + 1) + 'InvalidSignature';

    verifier.verify(invalidSignatureData, payload.aud, function (error, tokenInfo) {
      assert.equal(_.isError(error), true);
      assert.equal(error.message, 'Invalid Signature');
      assert.equal(_.isEmpty(tokenInfo), true);
      done();
    });
  });

  it('should fail to verify payload if audience is invalid', function (done) {
    var payload = makeValidPayload(_.clone(testToken));
    payload.aud = 'invalid.audience.domain';
    var envelope = _.clone(testEnvelope);
    var data = makeFakeIdToken(payload, envelope);

    verifier.verify(data, testToken.aud, function (error, tokenInfo) {
      assert.equal(_.isError(error), true);
      assert.equal(error.message, 'Invalid idToken audience');
      assert.equal(_.isEmpty(tokenInfo), true);
      done();
    });
  });

  it('should fail to verify payload if idToken is expired', function (done) {
    var payload = makeValidPayload(_.clone(testToken));
    payload.exp = new Date(0).getTime() / 1000;
    var envelope = _.clone(testEnvelope);
    var data = makeFakeIdToken(payload, envelope);

    verifier.verify(data, payload.aud, function (error, tokenInfo) {
      assert.equal(_.isError(error), true);
      assert.equal(error.message, 'Expired idToken');
      assert.equal(_.isEmpty(tokenInfo), true);
      done();
    });
  });
});
