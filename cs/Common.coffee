Base58 = require "base-58"
Crypto = require "crypto"

#.my-card-content {
#  padding: 16px;
#}
#.my-card {
#  height: 100px;
#  width: 300px;
#}
export PRIVATE_KEY_SIZE = 256 / 8
export DECODED_COMPRESSED_PRIVATE_KEY_SIZE = 1 + PRIVATE_KEY_SIZE + 1 + 4
export DECODED_UNCOMPRESSED_PRIVATE_KEY_SIZE = 1 + PRIVATE_KEY_SIZE + 4
export MAX_PRIVATE_KEY = Buffer.from("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364140", 'hex')
export MIN_PRIVATE_KEY = Buffer.from("0000000000000000000000000000000000000000000000000000000000000001", 'hex')

export generatePrivateKey = () ->
  buffer = Buffer.alloc(PRIVATE_KEY_SIZE)
  Crypto.randomFillSync(buffer)

  while buffer.compare(MIN_PRIVATE_KEY) < 0 or buffer.compare(MAX_PRIVATE_KEY) > 0
    Crypto.randomFillSync(buffer)

  return buffer

export hexPrivateKeyValidator = (text) ->
  return false if text.length != PRIVATE_KEY_SIZE*2 or text.match(/^[0-9a-fA-F]+$/) == null
  key = Buffer.from(text, 'hex')
  return false if key.compare(MIN_PRIVATE_KEY) < 0 or key.compare(MAX_PRIVATE_KEY) > 0
  return true

export wifValidator = (text) ->
  [ valid ] = decodeWif(text)
  return valid

export encodeWif = (prefix, key, compressed) ->
  if compressed
    work = Buffer.concat([ Buffer.alloc(1, prefix), key, Buffer.alloc(1, 0x01) ])
  else
    work = Buffer.concat([ Buffer.alloc(1, prefix), key ])

  checksum = computeChecksum(work)
  work = Buffer.concat([ work, checksum ])
  wif = Base58.encode(work)

  return [ wif, checksum ]

export decodeWif = (wif) ->
  return [ false ] if wif.match(/^[123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz]+$/) == null

  work = Buffer.from(Base58.decode(wif))

  if work.length == DECODED_UNCOMPRESSED_PRIVATE_KEY_SIZE
    prefix = work[0]
    privateKey = work.slice(1, 1 + PRIVATE_KEY_SIZE)
    checksum = work.slice(1 + PRIVATE_KEY_SIZE)
    computed = computeChecksum(work.slice(0, 1 + PRIVATE_KEY_SIZE))
    return [ true, false, prefix, privateKey, checksum ] if checksum.compare(computed) == 0
  else if work.length == DECODED_COMPRESSED_PRIVATE_KEY_SIZE
    prefix = work[0]
    privateKey = work.slice(1, 1 + PRIVATE_KEY_SIZE)
    compressed = work[1 + PRIVATE_KEY_SIZE]
    checksum = work.slice(1 + PRIVATE_KEY_SIZE + 1)
    computed = computeChecksum(work.slice(0, 1 + PRIVATE_KEY_SIZE + 1))
    return [ true, true, prefix, privateKey, checksum ] if checksum.compare(computed) == 0 and compressed == 1
  return [ false ]

export computeChecksum = (buffer) ->
  hash1 = Crypto.createHash('sha256')
  hash1.update buffer

  hash2 = Crypto.createHash('sha256')
  hash2.update hash1.digest()

  return hash2.digest().slice(0, 4)

