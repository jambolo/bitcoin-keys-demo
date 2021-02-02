Base58 = require "base-58"
Crypto = require "crypto"

#.my-card-content {
#  padding: 16px;
#}
#.my-card {
#  height: 100px;
#  width: 300px;
#}
CHECKSUM_BITS = 32
CHECKSUM_SIZE = CHECKSUM_BITS / 8
PRIVATE_KEY_BITS = 256
export PRIVATE_KEY_SIZE = PRIVATE_KEY_BITS / 8
export DECODED_COMPRESSED_PRIVATE_KEY_SIZE = 1 + PRIVATE_KEY_SIZE + 1 + CHECKSUM_SIZE
export DECODED_UNCOMPRESSED_PRIVATE_KEY_SIZE = 1 + PRIVATE_KEY_SIZE + CHECKSUM_SIZE
export MAX_PRIVATE_KEY = Buffer.from("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364140", 'hex')
export MIN_PRIVATE_KEY = Buffer.from("0000000000000000000000000000000000000000000000000000000000000001", 'hex')
PUBLIC_KEY_COORD_BITS = 256
export COMPRESSED_PUBLIC_KEY_SIZE = 1 + PUBLIC_KEY_COORD_BITS / 8
export UNCOMPRESSED_PUBLIC_KEY_SIZE = 1 + PUBLIC_KEY_COORD_BITS / 8 * 2
PUBKEYHASH_BITS = 160
PUBKEYHASH_SIZE = PUBKEYHASH_BITS / 8
DECODED_BASE58_ADDRESS_SIZE = 1 + PUBKEYHASH_SIZE + CHECKSUM_SIZE
export P2PKH_PREFIX = 0
export P2SH_PREFIX = 5

debugging = false
debuggingIndent = 1
logIfDebugging = (args...) ->
  if debugging
    indent = '| '.repeat(debuggingIndent)
    console.log indent, ...args
  return

logEnterIfDebugging = (args...) ->
  if debugging
    indent = '| '.repeat(debuggingIndent)
    console.log indent, ...args
    ++debuggingIndent
  return

logExitIfDebugging = (args...) ->
  if debugging
    indent = '| '.repeat(debuggingIndent)
    console.log indent, ...args
    --debuggingIndent
  return

export base58IsValid = (text) ->
  text.toString().match(/^[123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz]+$/) != null

export hexIsValid = (hex) ->
  hex.toString().match(/^[0-9a-fA-F]+$/) != null

export checksumIsValid = (data) ->
  logEnterIfDebugging "checksumIsValid: (data=#{data.toString('hex')})"

  check = data[-CHECKSUM_SIZE...]
  computed = checksum(data[...-CHECKSUM_SIZE])
  logIfDebugging "checksumIsValid: check=#{check.toString('hex')}, computed=#{computed.toString('hex')}"

  valid = check.compare(computed) == 0

  logExitIfDebugging "checksumIsValid: returning #{valid.toString()}"
  return valid

privateKeyIsValid = (key) ->
  logEnterIfDebugging "privateKeyIsValid: (key=#{key.toString('hex')})"

  logExitIfDebugging "privateKeyIsValid: key.length=#{key.length}" if key.length != PRIVATE_KEY_SIZE
  return false if key.length != PRIVATE_KEY_SIZE

  logExitIfDebugging "privateKeyIsValid: key=#{key.toString('hex')}" if key.compare(MIN_PRIVATE_KEY) < 0 or key.compare(MAX_PRIVATE_KEY) > 0
  return false if key.compare(MIN_PRIVATE_KEY) < 0 or key.compare(MAX_PRIVATE_KEY) > 0

  logExitIfDebugging "privateKeyIsValid: returning true"
  return true

export hexIsValidPrivateKey = (hex) ->
  logEnterIfDebugging "hexIsValidPrivateKey: (hex=#{hex.toString()})"

  logExitIfDebugging "hexIsValidPrivateKey: hexIsValid returned #{hexIsValid(hex)}" if not hexIsValid(hex) 
  return false if not hexIsValid(hex)

  logExitIfDebugging "hexIsValidPrivateKey: hex.length=#{hex.length}" if hex.length != PRIVATE_KEY_SIZE*2
  return false if hex.length != PRIVATE_KEY_SIZE*2

  key = Buffer.from(hex.toString(), 'hex')
  valid = privateKeyIsValid(key)

  logExitIfDebugging "hexIsValidPrivateKey: returning #{valid.toString()}"
  return valid

export wifIsValid = (wif) ->
  logEnterIfDebugging "wifIsValid: (wif=#{wif.toString()})"

  [ valid ] = decodedWif(wif)

  logExitIfDebugging "wifIsValid: returning #{valid.toString()}"
  return valid


publicKeyIsValid = (key) ->
  logEnterIfDebugging "publicKeyIsValid: (key=#{key.toString('hex')})"

  logExitIfDebugging "publicKeyIsValid: key[0]=#{key[0]}" if key[0] != 2 and key[0] != 3 and key[0] != 4
  return false if key[0] != 2 and key[0] != 3 and key[0] != 4

  logExitIfDebugging "publicKeyIsValid: key[0]=#{key[0]}, key.length=#{key.length}" if (key[0] == 2 or key[0] == 3) and key.length != COMPRESSED_PUBLIC_KEY_SIZE
  return false if (key[0] == 2 or key[0] == 3) and key.length != COMPRESSED_PUBLIC_KEY_SIZE

  logExitIfDebugging "publicKeyIsValid: key[0]=#{key[0]}, key.length=#{key.length}" if key[0] == 4 and key.length != UNCOMPRESSED_PUBLIC_KEY_SIZE
  return false if key[0] == 4 and key.length != UNCOMPRESSED_PUBLIC_KEY_SIZE

  logExitIfDebugging "publicKeyIsValid: returning true"
  return true

export hexIsValidPublicKey = (hex) ->
  logEnterIfDebugging "hexIsValidPublicKey: (hex=#{hex.toString()})"

  logExitIfDebugging "hexIsValidPublicKey: hexIsValid returned #{hexIsValid(hex)}" if not hexIsValid(hex) 
  return if not hexIsValid(hex)

  logExitIfDebugging "hexIsValidPublicKey: hex.length=#{hex.length}" if hex.length != COMPRESSED_PUBLIC_KEY_SIZE * 2 and hex.length != UNCOMPRESSED_PUBLIC_KEY_SIZE * 2 
  return false if hex.length != COMPRESSED_PUBLIC_KEY_SIZE * 2 and hex.length != UNCOMPRESSED_PUBLIC_KEY_SIZE * 2 

  key = Buffer.from(hex.toString(), 'hex')
  valid = publicKeyIsValid(key)

  logExitIfDebugging "hexIsValidPublicKey: returning #{valid.toString()}"
  return valid

pubkeyHashIsValid = (hash) ->
  logEnterIfDebugging "pubkeyHashIsValid: (hash=#{hash.toString('hex')})"

  logExitIfDebugging "pubkeyHashIsValid: hash.length=#{}{hash.length}" if hash.length != PUBKEYHASH_SIZE
  return false if hash.length != PUBKEYHASH_SIZE

  logExitIfDebugging "pubkeyHashIsValid: returning true"
  return true

hexIsValidPubkeyHash = (hex) ->
  logEnterIfDebugging "hexIsValidPubkeyHash: (hex=#{hex.toString()})"

  logExitIfDebugging "hexIsValidPubkeyHash: hexIsValid returned #{hexIsValid(hex)}" if not hexIsValid(hex) 
  return if not hexIsValid(hex)

  logExitIfDebugging "hexIsValidPubkeyHash: hex.length=#{hex.length}" if hex.length != PUBKEYHASH_SIZE * 2
  return false if hex.length != PUBKEYHASH_SIZE * 2 

  hash = Buffer.from(hex.toString(), 'hex')
  valid = pubkeyHashIsValid(hash)

  logExitIfDebugging "hexIsValidPubkeyHash: returning #{valid.toString()}"
  return valid


checksum = (data) ->
  logEnterIfDebugging "checksum: (data=#{data.toString('hex')})"

  hash1 = Crypto.createHash('sha256').update(data).digest()
  hash2 = Crypto.createHash('sha256').update(hash1).digest()
  check = hash2[...CHECKSUM_SIZE]

  logExitIfDebugging "checksum: returning #{check.toString('hex')}"
  return check

base58Check = (data) ->
  logEnterIfDebugging "base58Check: (data=#{data.toString('hex')})"

  check = checksum(data)
  work = Buffer.concat([ data, check ])
  encoded = Buffer.from(Base58.encode(work))

  logExitIfDebugging "base58Check: returning [ #{encoded.toString()}, #{check.toString('hex')} ]"
  return [ encoded, check ]

export generatedPrivateKey = () ->
  key = Buffer.alloc(PRIVATE_KEY_SIZE)
  Crypto.randomFillSync(key)

  while key.compare(MIN_PRIVATE_KEY) < 0 or key.compare(MAX_PRIVATE_KEY) > 0
    Crypto.randomFillSync(key)

  return key

export generatedWif = () ->
  [ encoded ] = encodedWif(generatedPrivateKey())
  return encoded

export encodedWif = (key, compressed = true, prefix = 0x80) ->
  logEnterIfDebugging "encodedWif: (key=#{key.toString('hex')}, compressed=#{compressed.toString()}, prefix=#{prefix})"

  if compressed
    work = Buffer.concat([ Buffer.alloc(1, prefix), key, Buffer.alloc(1, 0x01) ])
  else
    work = Buffer.concat([ Buffer.alloc(1, prefix), key ])
  encoded = base58Check(work)

  logExitIfDebugging "encodedWif: returning #{encoded[0].toString()}"
  return encoded

export decodedWif = (wif) ->
  logEnterIfDebugging "decodedWif: (wif=#{wif.toString()})"

  logExitIfDebugging "decodedWif: base58IsValid(wif) returned #{base58IsValid(wif)}" if not base58IsValid(wif)
  return [ false ] if not base58IsValid(wif)

  work = Buffer.from(Base58.decode(wif.toString()))
  logExitIfDebugging "decodedWif: work.length=#{work.length}" if work.length < DECODED_UNCOMPRESSED_PRIVATE_KEY_SIZE or work.length > DECODED_COMPRESSED_PRIVATE_KEY_SIZE
  return [ false ] if work.length < DECODED_UNCOMPRESSED_PRIVATE_KEY_SIZE or work.length > DECODED_COMPRESSED_PRIVATE_KEY_SIZE

  logExitIfDebugging "decodedWif: checksumIsValid(work) returned #{checksumIsValid(work)}" if not checksumIsValid(work)
  return [ false ] if not checksumIsValid(work)

  compressed = work.length == DECODED_COMPRESSED_PRIVATE_KEY_SIZE and work[1 + PRIVATE_KEY_SIZE] == 1
  logExitIfDebugging "decodedWif: work.length=#{work.length}, work[1 + PRIVATE_KEY_SIZE]=#{work[1 + PRIVATE_KEY_SIZE]}" if work.length == DECODED_COMPRESSED_PRIVATE_KEY_SIZE and work[1 + PRIVATE_KEY_SIZE] != 1
  return [ false ] if work.length == DECODED_COMPRESSED_PRIVATE_KEY_SIZE and work[1 + PRIVATE_KEY_SIZE] != 1

  prefix = work[0]
  privKey = work[1...1 + PRIVATE_KEY_SIZE]
  check = work[-CHECKSUM_SIZE...]

  logExitIfDebugging "decodedWif: returning [ true, #{privKey.toString('hex')}, #{compressed}, #{check.toString('hex')}, #{prefix} ]"
  return [ true, privKey, compressed, check, prefix ]

export publicKey = (privKey, compressed) ->
  logEnterIfDebugging "publicKey: (privKey=#{privKey.toString("hex")}, compressed=#{compressed.toString()}"

  ecdh = Crypto.createECDH('secp256k1')
  ecdh.setPrivateKey privKey
  key = ecdh.getPublicKey(null, if compressed then "compressed" else "uncompressed")

  logExitIfDebugging "publicKey: returning #{key.toString("hex")}"
  return key

export pubkeyHash = (pubKey) ->
  logEnterIfDebugging "pubKey: (pubKey=#{pubKey.toString('hex')})"

  hash1 = Crypto.createHash('sha256').update(pubKey).digest()
  hash2 = Crypto.createHash('ripemd160').update(hash1).digest()
  
  logExitIfDebugging "pubkeyHash: returning #{hash2.toString('hex')}"
  return hash2

export base58Address = (pubKey, prefix = 0) ->
  logEnterIfDebugging "base58Address: (pubKey=#{pubKey.toString('hex')}, prefix=#{prefix})"

  hash = pubkeyHash(pubKey)
  [ encoded, check ] = base58EncodedAddress(hash, prefix)

  logExitIfDebugging "base58Address: returning [ #{encoded.toString()}, #{check.toString('hex')} ]"
  return [ encoded, check ]

export base58EncodedAddress = (hash, prefix = 0) ->
  logEnterIfDebugging "base58EncodedAddress: (hash=#{hash.toString('hex')}, prefix=#{prefix})"

  work = Buffer.concat([ Buffer.alloc(1, prefix), hash ])
  [ encoded, check ] = base58Check(work)

  logExitIfDebugging "base58EncodedAddress: returning [ #{encoded.toString()}, #{check.toString('hex')} ]"
  return [ encoded, check ]

export decodedBase58Address = (addr) ->
  logEnterIfDebugging "decodedBase58Address: (addr=#{addr.toString()})"

  logExitIfDebugging "decodedBase58Address: base58IsValid(addr) returned #{base58IsValid(addr)}" if not base58IsValid(addr)
  return [ false ] if not base58IsValid(addr)

  work = Buffer.from(Base58.decode(addr.toString()))
  logExitIfDebugging "decodedBase58Address: work.length=#{work.length}, checksumIsValid(work) returned #{checksumIsValid(work)}" if work.length != DECODED_BASE58_ADDRESS_SIZE or not checksumIsValid(work)
  return [ false ] if work.length != DECODED_BASE58_ADDRESS_SIZE or not checksumIsValid(work)

  prefix = work[0]
  hash = work[1...1 + PUBKEYHASH_SIZE]
  check = work[-CHECKSUM_SIZE...]

  logExitIfDebugging "decodedBase58Address: returning [ true, #{hash.toString('hex')}, #{prefix}, #{check.toString('hex')} ]"
  return [ true, hash, prefix, check ]
