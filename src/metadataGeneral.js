'use strict';

var WalletCrypto = require('./wallet-crypto');
var Bitcoin = require('bitcoinjs-lib');
var API = require('./api');
var Helpers = require('./helpers');
var MyWallet = require('./wallet');
import * as R from 'ramda'

////////////////////////////////////////////////////////////////////////////////

class MetadataGeneral {
  constructor (ecPair, encKeyBuffer, typeId) {
    // ecPair :: ECPair object - bitcoinjs-lib
    // encKeyBuffer :: Buffer (nullable = no encrypted save)
    // TypeId :: Int (nullable = default -1)
    this.VERSION = 1;
    this._typeId = typeId || -1;
    this._magicHash = null;
    this._address = ecPair.getAddress()
    this._signKey = ecPair;
    this._encKeyBuffer = encKeyBuffer;
    this._sequence = Promise.resolve();
  }

  get existsOnServer() {
    return Boolean(this._magicHash);
  }
}

////////////////////////////////////////////////////////////////////////////////
// network
MetadataGeneral.request = function (method, endpoint, data) {
  const url = API.API_ROOT_URL + 'metadata/' + endpoint;
  let options = {
    headers: { 'Content-Type': 'application/json' },
    credentials: 'omit'
  };
  if (method !== 'GET') {
    options.body = JSON.stringify(data);
  }
  options.method = method;
  const handleNetworkError = (e) =>
    Promise.reject({ error: 'METADATA_CONNECT_ERROR', message: e });

  const checkStatus = (response) => {
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

MetadataGeneral.GET = function (e, d) { return MetadataGeneral.request('GET', e, d); };
MetadataGeneral.PUT = function (e, d) { return MetadataGeneral.request('PUT', e, d); };
MetadataGeneral.read = (address) => MetadataGeneral.request('GET', address)
                                      .then(MetadataGeneral.extractResponse(null));

////////////////////////////////////////////////////////////////////////////////
MetadataGeneral.encrypt = R.curry((key, data) => WalletCrypto.encryptDataWithKey(data, key));
MetadataGeneral.decrypt = R.curry((key, data) => WalletCrypto.decryptDataWithKey(data, key));
MetadataGeneral.B64ToBuffer = (base64) => Buffer.from(base64, 'base64');
MetadataGeneral.BufferToB64 = (buff) => buff.toString('base64');
MetadataGeneral.b64EncodeUnicode = (str) => {
    return btoa(encodeURIComponent(str).replace(/%([0-9A-F]{2})/g, function(match, p1) {
        return String.fromCharCode('0x' + p1);
    }));
}
MetadataGeneral.b64DecodeUnicode = (str) => {
    return decodeURIComponent(Array.prototype.map.call(atob(str), function(c) {
        return '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2);
    }).join(''));
}

// Buffer -> Buffer -> Base64String
MetadataGeneral.message = R.curry(
  function (payload, prevMagic) {
    if (prevMagic) {
      const hash = WalletCrypto.sha256(payload);
      const buff = Buffer.concat([prevMagic, hash]);
      return buff.toString('base64');
    } else {
      return payload.toString('base64');
    }
  }
)

// Buffer -> Buffer -> Buffer
MetadataGeneral.magic = R.curry(
  function (payload, prevMagic) {
    const msg = this.message(payload, prevMagic);
    return Bitcoin.message.magicHash(msg, Bitcoin.networks.bitcoin);
  }
)

MetadataGeneral.verify = (address, signature, hash) =>
  Bitcoin.message.verify(address, signature, hash);

// MetadataGeneral.sign :: keyPair -> msg -> Buffer
MetadataGeneral.sign = (keyPair, msg) => Bitcoin.message.sign(keyPair, msg, Bitcoin.networks.bitcoin)
MetadataGeneral.computeSignature = (key, payloadBuff, magicHash) =>
  MetadataGeneral.sign(key, MetadataGeneral.message(payloadBuff, magicHash))

MetadataGeneral.verifyResponse = R.curry((address, res) => {
  if (res === null) return res;
  const M = MetadataGeneral;
  const sB = res.signature ? Buffer.from(res.signature, 'base64') : undefined;
  const pB = res.payload ? Buffer.from(res.payload, 'base64') : undefined;
  const mB = res.prev_magic_hash ? Buffer.from(res.prev_magic_hash, 'hex') : undefined;
  const verified = MetadataGeneral.verify(address, sB, M.message(pB, mB));
  if (!verified) throw new Error('METADATA_SIGNATURE_VERIFICATION_ERROR');
  return R.assoc('compute_new_magic_hash', M.magic(pB, mB), res);
})

MetadataGeneral.extractResponse = R.curry((encKey, res) => {
  const M = MetadataGeneral;
  if (res === null) {
    return res;
  } else {
    return encKey ?
      R.compose(JSON.parse, M.decrypt(encKey), R.prop('payload'))(res) :
      R.compose(JSON.parse, M.b64DecodeUnicode, R.prop('payload'))(res);
  }
})

////////////////////////////////////////////////////////////////////////////////

MetadataGeneral.prototype.create = function (payload) {
  return this.next(() => {
    const M = MetadataGeneral;
    const encPayloadBuffer = this._encKeyBuffer ?
      R.compose(M.B64ToBuffer, M.encrypt(this._encKeyBuffer), JSON.stringify)(payload) :
      R.compose(M.B64ToBuffer, M.b64EncodeUnicode, JSON.stringify)(payload);
    const signatureBuffer = M.computeSignature(this._signKey, encPayloadBuffer, this._magicHash);
    const body = {
      'version': this.VERSION,
      'payload': encPayloadBuffer.toString('base64'),
      'signature': signatureBuffer.toString('base64'),
      'prev_magic_hash': this._magicHash ? this._magicHash.toString('hex') : null,
      'type_id': this._typeId
    };
    return M.PUT(this._address, body).then(
      (response) => {
        this._value = payload;
        this._magicHash = M.magic(encPayloadBuffer, this._magicHash);
        return payload;
      }
    );
  });
}

////////////////////////////////////////////////////////////////////////////////
MetadataGeneral.prototype.update = function (payload) {
  if (JSON.stringify(payload) === JSON.stringify(this._value)){
    return this.next(()=> Promise.resolve(payload));
  } else {
    return this.create(payload);
  }
}

////////////////////////////////////////////////////////////////////////////////
MetadataGeneral.prototype.fetch = function () {
  return this.next(() => {
    const M = MetadataGeneral;
    const saveMagicHash = (res) => {
      this._magicHash = R.prop('compute_new_magic_hash', res);
      return res;
    }
    const saveValue = (res) => {
      this._value = res;
      return res;
    }
    return M.GET(this._address).then(M.verifyResponse(this._address))
                               .then(saveMagicHash)
                               .then(M.extractResponse(this._encKeyBuffer))
                               .then(saveValue)
                               .catch((e) => Promise.reject('METADATA_FETCH_FAILED'));
  });
}

////////////////////////////////////////////////////////////////////////////////
MetadataGeneral.prototype.next = function (f) {
  var nextInSeq = this._sequence.then(f);
  this._sequence = nextInSeq.then(Helpers.noop, Helpers.noop);
  return nextInSeq;
};

////////////////////////////////////////////////////////////////////////////////
// CONSTRUCTORS
// used to restore metadata from purpose xpriv (second password)
MetadataGeneral.fromMetadataHDNode = function (metadataHDNode, typeId) {
  // Payload types:
  // 0: reserved (guid)
  // 1: reserved
  // 2: whats-new
  // 3: buy-sell
  // 4: contacts
  const payloadTypeNode = metaDataHDNode.deriveHardened(TypeId);
  // purpose' / type' / 0' : https://meta.blockchain.info/{address}
  //                       signature used to authenticate
  // purpose' / type' / 1' : sha256(private key) used as 256 bit AES key
  const node = payloadTypeNode.deriveHardened(0);
  const privateKeyBuffer = payloadTypeNode.deriveHardened(1).keyPair.d.toBuffer();
  const encryptionKey = WalletCrypto.sha256(privateKeyBuffer);
  return new MetadataGeneral(node.keyPair, encryptionKey, typeId);
}

// used to create a new metadata entry from wallet master hd node
MetadataGeneral.fromMasterHDNode = function (masterHDNode, typeId) {
  // BIP 43 purpose needs to be 31 bit or less. For lack of a BIP number
  // we take the first 31 bits of the SHA256 hash of a reverse domain.
  var hash = WalletCrypto.sha256('info.blockchain.metadata');
  var purpose = hash.slice(0, 4).readUInt32BE(0) & 0x7FFFFFFF; // 510742
  var metaDataHDNode = masterHDNode.deriveHardened(purpose);
  return MetadataGeneral.fromMetadataHDNode(metadataHDNode, typeId);
}

module.exports = MetadataGeneral;
