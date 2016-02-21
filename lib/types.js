var typeforce = require('typeforce')

function nBuffer (value, n) {
  typeforce(types.Buffer, value)
  if (value.length !== n) throw new typeforce.TfTypeError('Expected ' + n + '-bytes Buffer, got ' + value.length + '-btyes Buffer')

  return true
}

function Buffer32bytes (value) { return nBuffer(value, 32) }
function Buffer33bytes (value) { return nBuffer(value, 33) }

function UInt8 (value) { return (value & 0xff) === value }
function UInt32 (value) { return (value >>> 0) === value }

var HDNodeConstructorObject = typeforce.oneOf.apply(null, [
  typeforce.compile({
    depth: typeforce.maybe(UInt8),
    parentFingerprint: typeforce.maybe(UInt32),
    index: typeforce.maybe(UInt32),
    chainCode: Buffer32bytes,
    privateKey: Buffer33bytes,
    publicKey: typeforce.maybe(Buffer33bytes)
  }),
  typeforce.compile({
    depth: typeforce.maybe(UInt8),
    parentFingerprint: typeforce.maybe(UInt32),
    index: typeforce.maybe(UInt32),
    chainCode: Buffer32bytes,
    privateKey: typeforce.maybe(Buffer33bytes),
    publicKey: Buffer33bytes
  })
])

function BIP32Path (value) {
  return typeforce.String(value) && value.match(/^(m\/)?(\d+'?\/)*\d+'?$/)
}

function BIP32Index (max) {
  return function (value) {
    typeforce(types.Number, value)
    if (value < 0 || value >= max) throw new typeforce.TfTypeError('Expected ' + value + ' in [0, ' + max + ')')

    return true
  }
}

var types = {
  HDNodeConstructorObject: HDNodeConstructorObject,
  BIP32Path: BIP32Path,
  BIP32Index: BIP32Index
}

for (var typeName in typeforce) {
  types[typeName] = typeforce[typeName]
}

module.exports = types
