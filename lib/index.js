'use strict'
var createHash = require('create-hash')
var createHmac = require('create-hmac')
var base58check = require('bs58check')
var randomBytes = require('randombytes')
var secp256k1 = require('secp256k1')
var typeforce = require('typeforce')

var types = require('./types')

module.exports = function (network) {
  function HDNode (obj) {
    typeforce(types.HDNodeConstructorObject, obj)

    this.depth = obj.depth || 0
    this.parentFingerprint = obj.parentFingerprint || 0
    this.index = obj.index || 0
    this.chainCode = obj.chainCode
    this.privateKey = obj.privateKey
    this.publicKey = obj.publicKey

    if (this.depth === 0) {
      if (this.parentFingerprint !== 0) throw new Error('Invalid parent fingerprint')
      if (this.index !== 0) throw new Error('Invalid index')
    }

    if (this.privateKey && !secp256k1.privateKeyVerify(this.privateKey)) throw new Error('Invalid private key')
    if (this.publicKey && !secp256k1.publicKeyVerify(this.publicKey)) throw new Error('Invalid public key')
  }

  HDNode.fromSeed = function (seed) {
    typeforce(types.Buffer, seed)

    if (seed.length < 16) throw new TypeError('Seed should be at least 128 bits')
    if (seed.length > 64) throw new TypeError('Seed should be at most 512 bits')

    var I = createHmac('sha512', network.masterSecret).update(seed).digest()
    var IL = I.slice(0, 32) // Invalid key handled in constructor
    var IR = I.slice(32)

    return new HDNode({
      depth: 0,
      parentFingerprint: 0,
      index: 0,
      chainCode: IR,
      privateKey: IL
    })
  }

  HDNode.fromRandomSeed = function () {
    while (true) {
      try {
        return HDNode.fromSeed(randomBytes(64))
      } catch (err) { continue }
    }
  }

  HDNode.fromString = function (string) {
    typeforce(types.String, string)

    var buffer = base58check.decode(string)
    if (buffer.length !== 78) throw new Error('Invalid buffer length')

    // 4 byte: version bytes
    var version = buffer.readUInt32BE(0)

    // 1 byte: depth: 0x00 for master nodes, 0x01 for level-1 descendants, ...
    var depth = buffer[4]

    // 4 bytes: the fingerprint of the parent's key (0x00000000 if master key)
    var parentFingerprint = buffer.readUInt32BE(5)

    // 4 bytes: child number. This is the number i in xi = xpar/i, with xi the key being serialized.
    // This is encoded in MSB order. (0x00000000 if master key)
    var index = buffer.readUInt32BE(9)

    // 32 bytes: the chain code
    var chainCode = buffer.slice(13, 45)

    var privateKey
    var publicKey
    switch (version) {
      // 33 bytes: private key data (0x00 + k)
      case network.bip32.private:
        if (buffer[45] !== 0) throw new Error('Invalid private key')
        privateKey = buffer.slice(46, 78)
        break
      // 33 bytes: public key data (0x02 + X or 0x03 + X)
      case network.bip32.public:
        publicKey = buffer.slice(45, 78)
        break
      default:
        throw new Error('Invalid network')
    }

    return new HDNode({
      depth: depth,
      parentFingerprint: parentFingerprint,
      index: index,
      chainCode: chainCode,
      privateKey: privateKey,
      publicKey: publicKey
    })
  }

  HDNode.prototype.getPrivateKey = function () {
    return this.privateKey.slice()
  }

  HDNode.prototype.getSerializedPrivateKey = function () {
    if (this.isNeutered()) throw new Error('HDNode is neutered')

    var buffer = new Buffer(78)
    buffer.writeUInt32BE(network.bip32.private, 0)
    buffer.writeUInt8(this.depth, 4)
    buffer.writeUInt32BE(this.parentFingerprint, 5)
    buffer.writeUInt32BE(this.index, 9)
    this.chainCode.copy(buffer, 13)
    buffer.writeUInt8(0, 45)
    this.privateKey.copy(buffer, 46)

    return base58check.encode(buffer)
  }

  HDNode.prototype.getPublicKey = function () {
    if (!this.publicKey) this.publicKey = secp256k1.publicKeyCreate(this.privateKey, true)
    return this.publicKey.slice()
  }

  HDNode.prototype.getSerializedPublicKey = function () {
    var buffer = new Buffer(78)
    buffer.writeUInt32BE(network.bip32.public, 0)
    buffer.writeUInt8(this.depth, 4)
    buffer.writeUInt32BE(this.parentFingerprint, 5)
    buffer.writeUInt32BE(this.index, 9)
    this.chainCode.copy(buffer, 13)
    this.getPublicKey().copy(buffer, 45)

    return base58check.encode(buffer)
  }

  HDNode.prototype.getFingerprint = function () {
    var buffer = createHash('sha256').update(this.getPublicKey()).digest()
    return createHash('rmd160').update(buffer).digest().slice(0, 4)
  }

  HDNode.prototype.derive = function (arg, isHardened) {
    if (Object.prototype.toString.call(arg) === '[Object String]') return this._deriveWithString(arg)
    return this._deriveWithNumber(arg, isHardened)
  }

  HDNode.prototype._deriveWithNumber = function (index, isHardened) {
    typeforce(types.BIP32Index(network.highestBit), index)
    typeforce(typeforce.maybe(types.Boolean), isHardened)

    var data = new Buffer(37)

    // Hardened child
    if (isHardened) {
      if (this.isNeutered()) throw new TypeError('Could not derive hardened child key')

      // data = 0x00 || ser256(kpar) || ser32(index)
      data[0] = 0x00
      this.privateKey.copy(data, 1)
      data.writeUInt32BE(index + network.highestBit, 33)

    // Normal child
    } else {
      // data = serP(point(kpar)) || ser32(index)
      //      = serP(Kpar) || ser32(index)
      this.getPublicKey().copy(data, 0)
      data.writeUInt32BE(index, 33)
    }

    var I = createHmac('sha512', this.chainCode).update(data).digest()
    var IL = I.slice(0, 32)
    var IR = I.slice(32)

    var privateKey
    var publicKey

    if (this.isNeutered()) {
      try {
        // throw if IL >= n || (privateKey + IL) === 0
        privateKey = secp256k1.privateKeyTweakAdd(this.privateKey, IL)
      } catch (err) { return this.derive(index + 1, isHardened) }
    } else {
      try {
        // throw if IL >= n || (g**IL + publicKey) is infinity
        publicKey = secp256k1.publicKeyTweakAdd(this.getPublicKey(), IL, true)
      } catch (err) { return this.derive(index + 1, isHardened) }
    }

    return new HDNode({
      depth: this.depth + 1,
      parentFingerprint: this.getFingerprint().readUInt32BE(0),
      index: index + (isHardened ? network.highestBit : 0),
      chainCode: IR,
      privateKey: privateKey,
      publicKey: publicKey
    })
  }

  HDNode.prototype._deriveWithString = function (path) {
    typeforce(types.BIP32Path, path)

    var splitPath = path.split('/')
    if (splitPath[0] === 'm') {
      if (this.parentFingerprint !== 0) throw new Error('Not a master node')
      splitPath = splitPath.slice(1)
    }

    return splitPath.reduce(function (parent, index) {
      if (index.slice(-1) !== "'") return parent.derive(index, false)
      return parent.derive(parseInt(index.slice(0, -1), 10), true)
    }, this)
  }

  HDNode.prototype.neutered = function () {
    if (this.isNeutered()) throw new Error('HDNode already neutered')

    return new HDNode({
      depth: this.depth,
      parentFingerprint: this.parentFingerprint,
      index: this.index,
      chainCode: this.chainCode,
      privateKey: null,
      publicKey: this.getPublicKey()
    })
  }

  HDNode.prototype.isNeutered = function () {
    return !this.privateKey
  }

  return HDNode
}
