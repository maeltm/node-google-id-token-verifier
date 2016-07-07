'use strict';

var _ = require('underscore');
var assert = require('assert');
var sinon = require('sinon');
var request = require('request');
var certCache = require('../lib/certCache');
var openid_configuration = require('./fixtures/openid-configuration');
var testOAuthCerts = require('./fixtures/oauthcerts');

describe('certCache', function () {
  before(function (done) {
    var cacheAge = (new Date().getTime() / 1000) + 1000;
    var stub = sinon.stub(request, 'get');
    stub
      .onFirstCall().yields(new Error('timeout'), { statusCode: 404, headers: {} }, null);
    stub
      .onSecondCall().yields(null, { statusCode: 200, headers: {} }, openid_configuration);
    stub
      .onThirdCall().yields(new Error('timeout'), { statusCode: 404, headers: {} }, null);
    stub
      .yields(null, { statusCode: 200, headers: {
        'cache-control': 'public, max-age=' + cacheAge + ', must-revalidate, no-transform'
        } }, testOAuthCerts);
    done();
  });

  after(function (done) {
    request.get.restore();
    done();
  });

  it('should succeed to get oauthcerts with refresh cache', function (done) {
    certCache.global.getFederatedGoogleCerts(function (err, keys) {
      assert.equal(_.isEmpty(err), false);
      assert.equal(request.get.callCount, 1);
      assert.equal(_.isEmpty(keys), true);
      certCache.global.getFederatedGoogleCerts(function (err, keys) {
        assert.equal(_.isEmpty(err), false);
        assert.equal(request.get.callCount, 3);
        assert.equal(_.isEmpty(keys), true);
        certCache.global.getFederatedGoogleCerts(function (err, keys) {
          assert.equal(_.isEmpty(err), true);
          assert.equal(request.get.callCount, 4);
          assert.equal(_.isEmpty(keys), false);
          certCache.global.getFederatedGoogleCerts(function (err, keys) {
            assert.equal(_.isEmpty(err), true);
            assert.equal(request.get.callCount, 4);
            assert.equal(_.isEmpty(keys), false);
            done();
          });
        });
      });
    });
  });
});
