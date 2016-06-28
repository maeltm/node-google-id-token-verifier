'use strict';

var request = require('request');

var GOOGLE_DISCOVERY_DOCUMENT_URL = 'https://accounts.google.com/.well-known/openid-configuration';

function CertCache() {
  this.googleOAuth2FederatedSignonCertsUrl = null;
  this.certificateExpiry = null;
  this.certificateCache = null;
}

CertCache.prototype.getFederatedGoogleCerts = function (callback) {
  var _this = this;
  var nowTime = (new Date()).getTime();
  if (_this.certificateExpiry && (nowTime < _this.certificateExpiry.getTime())) {
    callback(null, this.certificateCache);
    return;
  }

  if (!_this.googleOAuth2FederatedSignonCertsUrl){
    _this.getGoogleCertsURI(callback);
    return;
  }

  var options = {
    uri: _this.googleOAuth2FederatedSignonCertsUrl,
    json: true
  };

  request.get(options, function (err, response, body) {
    if (err) {
      callback('Failed to retrieve verification certificates: ' + err, null, response);
      return;
    }

    var cacheControl = response.headers['cache-control'];
    var cacheAge = -1;

    if (cacheControl) {
      var pattern = new RegExp('max-age=([0-9]*)');
      var regexResult = pattern.exec(cacheControl);
      if (regexResult.length === 2) {
        // Cache results with max-age (in seconds)
        cacheAge = regexResult[1] * 1000; // milliseconds
      }
    }

    var now = new Date();
    _this.certificateExpiry = (cacheAge === -1 ? null : new Date(now.getTime() + cacheAge));
    _this.certificateCache = body;
    callback(null, body, response);
  });
};

CertCache.prototype.getGoogleCertsURI = function (callback) {
  var _this = this;
  var options = {
    uri: GOOGLE_DISCOVERY_DOCUMENT_URL,
    json: true
  };

  request.get(options, function (err, response, body) {
    if (err) {
      callback('Failed to retrieve discovery document: ' + err, null, response);
      return;
    }
    _this.googleOAuth2FederatedSignonCertsUrl = body.jwks_uri;
    _this.getFederatedGoogleCerts(callback);
  });

};

CertCache.global = new CertCache();

module.exports = CertCache;
