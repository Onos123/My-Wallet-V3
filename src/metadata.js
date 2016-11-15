'use strict';

var WalletCrypto = require('./wallet-crypto');
var Bitcoin = require('bitcoinjs-lib');
var API = require('./api');
var Helpers = require('./helpers');
var MyWallet = require('./wallet');

module.exports = Metadata;

function Metadata (payloadType, cipher) {
  this.VERSION = 1;
  this._payloadTypeId = payloadType;
  this._magicHash = null;
  this._value = null;
  this._sequence = Promise.resolve();

  // BIP 43 purpose needs to be 31 bit or less. For lack of a BIP number
  // we take the first 31 bits of the SHA256 hash of a reverse domain.
  var hash = WalletCrypto.sha256('info.blockchain.metadata');
  var purpose = hash.slice(0, 4).readUInt32BE(0) & 0x7FFFFFFF; // 510742

  var masterHDNode = MyWallet.wallet.hdwallet.getMasterHDNode(cipher);
  var metaDataHDNode = masterHDNode.deriveHardened(purpose);

  // Payload types:
  // 0: reserved
  // 1: reserved
  // 2: whats-new

  var payloadTypeNode = metaDataHDNode.deriveHardened(payloadType);
  // purpose' / type' / 0' : https://meta.blockchain.info/{address}
  //                       signature used to authenticate
  // purpose' / type' / 1' : sha256(private key) used as 256 bit AES key
  var node = payloadTypeNode.deriveHardened(0);

  this._address = node.getAddress();
  this._signatureKeyPair = node.keyPair;

  var privateKeyBuffer = payloadTypeNode.deriveHardened(1).keyPair.d.toBuffer();
  this._encryptionKey = WalletCrypto.sha256(privateKeyBuffer);
}

// Buffer -> Buffer -> Base64String
Metadata.prototype.message = function (payload, prev) {
  if (prev) {
    var hash = WalletCrypto.sha256(payload);
    var buff = Buffer.concat([prev, hash]);
    return buff.toString('base64');
  } else {
    return payload.toString('base64');
  }
};

// Buffer -> Buffer -> Buffer
Metadata.prototype.magic = function (payload, prev) {
  var msg = this.message(payload, prev);
  return Bitcoin.message.magicHash(msg, Bitcoin.networks.bitcoin);
};

Metadata.prototype.sign = function (key, msg) {
  return Bitcoin.message.sign(key, msg);
};

Object.defineProperties(Metadata.prototype, {
  'existsOnServer': {
    configurable: false,
    get: function () { return Boolean(this._magicHash); }
  }
});

Metadata.prototype.create = function (payload) {
  var self = this;
  return this.next(
    function () {
      var payloadString = JSON.stringify(payload);
      var encPayloadBuffer = Buffer.from(WalletCrypto.encryptDataWithKey(payloadString, self._encryptionKey), 'base64');
      var nextMagicHash = self.magic(encPayloadBuffer, self._magicHash);
      var signatureBuffer = self.sign(self._signatureKeyPair, self.message(encPayloadBuffer, self._magicHash));
      var obj = {
        'version': 1,
        'payload': encPayloadBuffer.toString('base64'),
        'signature': signatureBuffer.toString('base64'),
        'prev_magic_hash': self._magicHash ? self._magicHash.toString('hex') : null,
        'type_id': self._payloadTypeId
      };
      return self.PUT(self._address, obj).then(
        function () {
          self._value = payload;
          self._magicHash = nextMagicHash;
        }
      );
    }
  );
};

Metadata.prototype.fetch = function () {
  var self = this;
  return this.next(function () {
    return self.GET(self._address).then(function (serverPayload) {
      if (serverPayload === null) {
        return null;
      }
      var decryptedPayload = WalletCrypto.decryptDataWithKey(serverPayload.payload, self._encryptionKey);
      var p = serverPayload.payload;
      var s = serverPayload.signature;
      var m = serverPayload.prev_magic_hash;
      var sB = s ? Buffer.from(s, 'base64') : undefined;
      var pB = p ? Buffer.from(p, 'base64') : undefined;
      var mB = m ? Buffer.from(m, 'hex') : undefined;
      var verified = Bitcoin.message.verify(self._address, sB, self.message(pB, mB));

      if (verified) {
        self._previousPayload = decryptedPayload;
        self._value = JSON.parse(decryptedPayload);
        self._magicHash = self.magic(pB, mB);
        return self._value;
      } else {
        throw new Error('METADATA_SIGNATURE_VERIFICATION_ERROR');
      }
    }).catch(function (e) {
      console.error(e);
      return Promise.reject('METADATA_FETCH_FAILED');
    });
  });
};

/*
metadata.update({
  lastViewed: Date.now()
});
*/
Metadata.prototype.update = Metadata.prototype.create;

Metadata.prototype.GET = function (endpoint, data) {
  // if (this._payloadTypeId === 3) {
  //   return Promise.reject('DEBUG: simulate meta data service failure');
  // }
  return this.request('GET', endpoint, data);
};

Metadata.prototype.PUT = function (endpoint, data) {
  return this.request('PUT', endpoint, data);
};

Metadata.prototype.request = function (method, endpoint, data) {
  var url = API.API_ROOT_URL + 'metadata/' + endpoint;

  var options = {
    headers: { 'Content-Type': 'application/json' },
    credentials: 'omit'
  };

  if (method !== 'GET') {
    options.body = JSON.stringify(data);
  }

  options.method = method;

  var handleNetworkError = function (e) {
    return Promise.reject({ error: 'METADATA_CONNECT_ERROR', message: e });
  };

  var checkStatus = function (response) {
    if (response.status >= 200 && response.status < 300) {
      return response.json();
    } else if (method === 'GET' && response.status === 404) {
      return null;
    } else {
      return response.text().then(Promise.reject.bind(Promise));
    }
  };

  return fetch(url, options)
    .catch(handleNetworkError)
    .then(checkStatus);
};

Metadata.prototype.next = function (f) {
  var nextInSeq = this._sequence.then(f);
  this._sequence = nextInSeq.then(Helpers.noop, Helpers.noop);
  return nextInSeq;
};
