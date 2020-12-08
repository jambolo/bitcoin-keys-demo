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

debugging = false

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
  if debugging
    console.log "hexIsValidPrivateKey: (text=#{text})"

  if debugging and (text.length != PRIVATE_KEY_SIZE*2 or not hexIsValid(text)) 
    console.log "hexIsValidPrivateKey: text.length=#{text.length}, hexIsValid returned #{hexIsValid(text)}"
  return false if text.length != PRIVATE_KEY_SIZE*2 or not hexIsValid(text)

  key = Buffer.from(text, 'hex')
  if debugging and (key.compare(MIN_PRIVATE_KEY) < 0 or key.compare(MAX_PRIVATE_KEY) > 0)
    console.log "hexIsValidPrivateKey: key=#{key.toString('hex')}"
  return false if key.compare(MIN_PRIVATE_KEY) < 0 or key.compare(MAX_PRIVATE_KEY) > 0

  if debugging
    console.log "hexIsValidPrivateKey: returning true"
  return true

export wifIsValid = (wif) ->
  if debugging
    console.log "wifIsValid: (wif=#{wif.toString('hex')})"

  [ valid ] = decodedWif(wif)

  if debugging
    console.log "wifIsValid: returning #{valid}"
  return valid

export encodedWif = (prefix, key, compressed) ->
  if debugging
    console.log "encodedWif: (prefix=#{prefix}, key=#{key.toString('hex')}, compressed=#{compressed})"

  if compressed
    work = Buffer.concat([ Buffer.alloc(1, prefix), key, Buffer.alloc(1, 0x01) ])
  else
    work = Buffer.concat([ Buffer.alloc(1, prefix), key ])
  encoded = base58Check(work)

  if debugging
    console.log "encodedWif: returning [ #{encoded[0].toString()}, #{encoded[1].toString('hex')} ]"
  return encoded

export decodedWif = (wif) ->
  if debugging
    console.log "decodedWif: (wif=#{wif.toString()})"

  if debugging and (not base58IsValid(wif))
    console.log "decodedWif: base58IsValid(wif) returned #{base58IsValid(wif)}"
  return [ false ] if not base58IsValid(wif)

  work = Buffer.from(Base58.decode(wif))
  if debugging and (work.length < DECODED_UNCOMPRESSED_PRIVATE_KEY_SIZE or work.length > DECODED_COMPRESSED_PRIVATE_KEY_SIZE)
    console.log "decodedWif: work.length=#{work.length}"
  return [ false ] if work.length < DECODED_UNCOMPRESSED_PRIVATE_KEY_SIZE or work.length > DECODED_COMPRESSED_PRIVATE_KEY_SIZE

  if debugging and (not checksumIsValid(work))
    console.log "decodedWif: checksumIsValid(work) returned #{checksumIsValid(work)}"
  return [ false ] if not checksumIsValid(work)

  compressed = work.length == DECODED_COMPRESSED_PRIVATE_KEY_SIZE and work[1 + PRIVATE_KEY_SIZE] == 1
  if debugging and (work.length == DECODED_COMPRESSED_PRIVATE_KEY_SIZE and work[1 + PRIVATE_KEY_SIZE] != 1)
    console.log "decodedWif: work.length=#{work.length}, work[1 + PRIVATE_KEY_SIZE]=#{work[1 + PRIVATE_KEY_SIZE]}"
  return [ false ] if work.length == DECODED_COMPRESSED_PRIVATE_KEY_SIZE and work[1 + PRIVATE_KEY_SIZE] != 1

  prefix = work[0]
  privateKey = work[1...1 + PRIVATE_KEY_SIZE]
  check = work[-CHECKSUM_SIZE...]

  if debugging
    console.log "decodedWif: returning { true, #{compressed}, #{prefix}, #{privateKey.toString('hex')}, #{check.toString('hex')} }"
  return [ true, compressed, prefix, privateKey, check ]

export encodedAddress = (prefix, pubkeyHash) ->
  if debugging
    console.log "encodedAddress: (prefix=#{prefix}, pubkeyHash=#{pubkeyHash.toString('hex')})"

  work = Buffer.concat([ Buffer.alloc(1, prefix), pubkeyHash ])
  encoded = base58Check(work)

  if debugging
    console.log "encodedAddress: returning #{encoded}"
  return encoded

export decodedAddress = (address) ->
  if debugging
    console.log "decodedAddress: (address=#{address})"

  if debugging and (not base58IsValid(address))
    console.log "decodedAddress: base58IsValid(address) returned #{base58IsValid(address)}"
  return [ false ] if not base58IsValid(address)

  work = Buffer.from(Base58.decode(address))
  if debugging and (work.length != DECODED_ADDRESS_SIZE or not checksumIsValid(work))
    console.log "decodedAddress: work.length=#{work.length}, checksumIsValid(work) returned #{checksumIsValid(work)}"
  return [ false ] if work.length != DECODED_ADDRESS_SIZE or not checksumIsValid(work)

  prefix = work[0]
  pubkeyHash = work[1...1 + PUBKEYHASH_SIZE]
  check = work[-CHECKSUM_SIZE...]

  if debugging
    console.log "decodedAddress: returning [ true, #{prefix}, #{pubkeyHash.toString('hex')}, #{check.toString('hex')} ]"
  return [ true, prefix, pubkeyHash, check ]

checksum = (data) ->
  if debugging
    console.log "checksum: (data=#{data.toString('hex')})"

  hash1 = Crypto.createHash('sha256').update(data).digest()
  hash2 = Crypto.createHash('sha256').update(hash1).digest()
  check = hash2[...CHECKSUM_SIZE]

  if debugging
    console.log "checksum: returning #{check.toString('hex')}"
  return check

base58Check = (data) ->
  if debugging
    console.log "base58Check: (data=#{data.toString('hex')})"

  check = checksum(data)
  work = Buffer.concat([ data, check ])
  encoded = Base58.encode(work)

  if debugging
    console.log "base58Check: returning [ #{encoded.toString('hex')}, #{check.toString('hex')} ]"
  return [ encoded, check ]

export checksumIsValid = (data) ->
  if debugging
    console.log "checksumIsValid: (data=#{data.toString('hex')})"

  check = data[-CHECKSUM_SIZE...]
  computed = checksum(data[...-CHECKSUM_SIZE])
  if debugging
    console.log "checksumIsValid: check=#{check.toString('hex')}, computed=#{computed.toString('hex')}"

  if debugging
    console.log "checksumIsValid returning #{check.compare(computed) == 0}"
  return check.compare(computed) == 0

export derivedPublicKey = (privatekey, compressed) ->
  Buffer.from("deadbeef", 'hex')