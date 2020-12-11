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
export PUBKEYHASH_SIZE = 160 / 8
CHECKSUM_SIZE = 4
export DECODED_COMPRESSED_PRIVATE_KEY_SIZE = 1 + PRIVATE_KEY_SIZE + 1 + CHECKSUM_SIZE
export DECODED_UNCOMPRESSED_PRIVATE_KEY_SIZE = 1 + PRIVATE_KEY_SIZE + CHECKSUM_SIZE
export MAX_PRIVATE_KEY = Buffer.from("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364140", 'hex')
export MIN_PRIVATE_KEY = Buffer.from("0000000000000000000000000000000000000000000000000000000000000001", 'hex')
export DECODED_ADDRESS_SIZE = 1 + PUBKEYHASH_SIZE + CHECKSUM_SIZE
export COMPRESSED_PUBLIC_KEY_SIZE = 1 + 256/8
export UNCOMPRESSED_PUBLIC_KEY_SIZE = 1 + 256/8*2

debugging = false
logIfDebugging = (args...) ->
  if debugging
    console.log ...args
  return

export generatedPrivateKey = () ->
  key = Buffer.alloc(PRIVATE_KEY_SIZE)
  Crypto.randomFillSync(key)

  while key.compare(MIN_PRIVATE_KEY) < 0 or key.compare(MAX_PRIVATE_KEY) > 0
    Crypto.randomFillSync(key)

  return key

export generatedWif = () ->
  [ encoded ] = encodedWif(0x80, generatedPrivateKey(), true)
  return encoded

export base58IsValid = (text) ->
  text.toString().match(/^[123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz]+$/) != null

export hexIsValid = (text) ->
  text.toString().match(/^[0-9a-fA-F]+$/) != null

export hexIsValidPrivateKey = (text) ->
  logIfDebugging "hexIsValidPrivateKey: (text=#{text})"

  logIfDebugging "hexIsValidPrivateKey: text.length=#{text.length}, hexIsValid returned #{hexIsValid(text)}"  if text.length != PRIVATE_KEY_SIZE*2 or not hexIsValid(text) 
  return false if text.length != PRIVATE_KEY_SIZE*2 or not hexIsValid(text)

  key = Buffer.from(text, 'hex')
  logIfDebugging "hexIsValidPrivateKey: key=#{key.toString('hex')}"  if key.compare(MIN_PRIVATE_KEY) < 0 or key.compare(MAX_PRIVATE_KEY) > 0
  return false if key.compare(MIN_PRIVATE_KEY) < 0 or key.compare(MAX_PRIVATE_KEY) > 0

  logIfDebugging "hexIsValidPrivateKey: returning true"
  return true

export wifIsValid = (wif) ->
  logIfDebugging "wifIsValid: (wif=#{wif.toString('hex')})"

  [ valid ] = decodedWif(wif)

  logIfDebugging "wifIsValid: returning #{valid}"
  return valid

export encodedWif = (prefix, key, compressed) ->
  logIfDebugging "encodedWif: (prefix=#{prefix}, key=#{key.toString('hex')}, compressed=#{compressed})"

  if compressed
    work = Buffer.concat([ Buffer.alloc(1, prefix), key, Buffer.alloc(1, 0x01) ])
  else
    work = Buffer.concat([ Buffer.alloc(1, prefix), key ])
  encoded = base58Check(work)

  logIfDebugging "encodedWif: returning [ #{encoded[0].toString()}, #{encoded[1].toString('hex')} ]"
  return encoded

export decodedWif = (wif) ->
  logIfDebugging "decodedWif: (wif=#{wif.toString()})"

  logIfDebugging "decodedWif: base58IsValid(wif) returned #{base58IsValid(wif)}"  if not base58IsValid(wif)
  return [ false ] if not base58IsValid(wif)

  work = Buffer.from(Base58.decode(wif))
  logIfDebugging "decodedWif: work.length=#{work.length}"  if work.length < DECODED_UNCOMPRESSED_PRIVATE_KEY_SIZE or work.length > DECODED_COMPRESSED_PRIVATE_KEY_SIZE
  return [ false ] if work.length < DECODED_UNCOMPRESSED_PRIVATE_KEY_SIZE or work.length > DECODED_COMPRESSED_PRIVATE_KEY_SIZE

  logIfDebugging "decodedWif: checksumIsValid(work) returned #{checksumIsValid(work)}"  if not checksumIsValid(work)
  return [ false ] if not checksumIsValid(work)

  compressed = work.length == DECODED_COMPRESSED_PRIVATE_KEY_SIZE and work[1 + PRIVATE_KEY_SIZE] == 1
  logIfDebugging "decodedWif: work.length=#{work.length}, work[1 + PRIVATE_KEY_SIZE]=#{work[1 + PRIVATE_KEY_SIZE]}"  if work.length == DECODED_COMPRESSED_PRIVATE_KEY_SIZE and work[1 + PRIVATE_KEY_SIZE] != 1
  return [ false ] if work.length == DECODED_COMPRESSED_PRIVATE_KEY_SIZE and work[1 + PRIVATE_KEY_SIZE] != 1

  prefix = work[0]
  privateKey = work[1...1 + PRIVATE_KEY_SIZE]
  check = work[-CHECKSUM_SIZE...]

  logIfDebugging "decodedWif: returning { true, #{compressed}, #{prefix}, #{privateKey.toString('hex')}, #{check.toString('hex')} }"
  return [ true, compressed, prefix, privateKey, check ]

export encodedAddress = (prefix, pubkeyHash) ->
  logIfDebugging "encodedAddress: (prefix=#{prefix}, pubkeyHash=#{pubkeyHash.toString('hex')})"

  work = Buffer.concat([ Buffer.alloc(1, prefix), pubkeyHash ])
  encoded = base58Check(work)

  logIfDebugging "encodedAddress: returning #{encoded}"
  return encoded

export decodedAddress = (address) ->
  logIfDebugging "decodedAddress: (address=#{address})"

  logIfDebugging "decodedAddress: base58IsValid(address) returned #{base58IsValid(address)}"  if not base58IsValid(address)
  return [ false ] if not base58IsValid(address)

  work = Buffer.from(Base58.decode(address))
  logIfDebugging "decodedAddress: work.length=#{work.length}, checksumIsValid(work) returned #{checksumIsValid(work)}"  if work.length != DECODED_ADDRESS_SIZE or not checksumIsValid(work)
  return [ false ] if work.length != DECODED_ADDRESS_SIZE or not checksumIsValid(work)

  prefix = work[0]
  pubkeyHash = work[1...1 + PUBKEYHASH_SIZE]
  check = work[-CHECKSUM_SIZE...]

  logIfDebugging "decodedAddress: returning [ true, #{prefix}, #{pubkeyHash.toString('hex')}, #{check.toString('hex')} ]"
  return [ true, prefix, pubkeyHash, check ]

checksum = (data) ->
  logIfDebugging "checksum: (data=#{data.toString('hex')})"

  hash1 = Crypto.createHash('sha256').update(data).digest()
  hash2 = Crypto.createHash('sha256').update(hash1).digest()
  check = hash2[...CHECKSUM_SIZE]

  logIfDebugging "checksum: returning #{check.toString('hex')}"
  return check

base58Check = (data) ->
  logIfDebugging "base58Check: (data=#{data.toString('hex')})"

  check = checksum(data)
  work = Buffer.concat([ data, check ])
  encoded = Base58.encode(work)

  logIfDebugging "base58Check: returning [ #{encoded.toString('hex')}, #{check.toString('hex')} ]"
  return [ encoded, check ]

export checksumIsValid = (data) ->
  logIfDebugging "checksumIsValid: (data=#{data.toString('hex')})"

  check = data[-CHECKSUM_SIZE...]
  computed = checksum(data[...-CHECKSUM_SIZE])
  logIfDebugging "checksumIsValid: check=#{check.toString('hex')}, computed=#{computed.toString('hex')}"

  logIfDebugging "checksumIsValid returning #{check.compare(computed) == 0}"
  return check.compare(computed) == 0

export derivedPublicKey = (privateKey, compressed) ->
  logIfDebugging "derivedPublicKey: (privateKey=#{privateKey.toString("hex")}, compressed=#{compressed.toString()}"

  ecdh = Crypto.createECDH('secp256k1')
  ecdh.setPrivateKey privateKey
  key = ecdh.getPublicKey(null, if compressed then "compressed" else "uncompressed")

  logIfDebugging "derivedPublicKey: returning #{key.toString("hex")}"
  return key

export hexIsValidPublicKey = (text) ->
  logIfDebugging "hexIsValidPublicKey: (text=#{text})"

  logIfDebugging "hexIsValidPublicKey: hexIsValid returned #{hexIsValid(text)}"  if not hexIsValid(text) 
  return if not hexIsValid(text)

  key = Buffer.from(text, 'hex')
  logIfDebugging "hexIsValidPublicKey: key[0]=#{key[0]}" if key[0] != 2 and key[0] != 3 and key[0] != 4
  return false if key[0] != 2 and key[0] != 3 and key[0] != 4

  logIfDebugging "hexIsValidPublicKey: key[0]=#{key[0]}, key.length=#{key.length}"  if (key[0] == 2 or key[0] == 3) and key.length != COMPRESSED_PUBLIC_KEY_SIZE
  return false if (key[0] == 2 or key[0] == 3) and key.length != COMPRESSED_PUBLIC_KEY_SIZE

  logIfDebugging "hexIsValidPublicKey: key[0]=#{key[0]}, key.length=#{key.length}"  if key[0] == 4 and key.length != UNCOMPRESSED_PUBLIC_KEY_SIZE
  return false if key[0] == 4 and key.length != UNCOMPRESSED_PUBLIC_KEY_SIZE

  logIfDebugging "hexIsValidPublicKey: returning true"
  return true

