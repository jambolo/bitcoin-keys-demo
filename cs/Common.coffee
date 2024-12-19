###
# Constants and utility functions for Bitcoin key and address validation.
#
###
Base58 = require "base-58"
Crypto = require "crypto"

#.my-card-content {
#  padding: 16px;
#}
#.my-card {
#  height: 100px;
#  width: 300px;
#}
###
# Constants:
# - CHECKSUM_BITS: Number of bits in the WIF checksum.
# - CHECKSUM_SIZE: Size of the WIF checksum in bytes.
# - PRIVATE_KEY_BITS: Number of bits in a private key.
# - PRIVATE_KEY_SIZE: Size of the private key in bytes.
# - DECODED_COMPRESSED_PRIVATE_KEY_SIZE: Size of a decoded compressed private key WIF.
# - DECODED_UNCOMPRESSED_PRIVATE_KEY_SIZE: Size of a decoded uncompressed private key WIF.
# - MAX_PRIVATE_KEY: Maximum value for a secp256k1 private key.
# - MIN_PRIVATE_KEY: Minimum value for a secp256k1 private key.
# - PUBLIC_KEY_COORD_BITS: Number of bits in a public key coordinate.
# - COMPRESSED_PUBLIC_KEY_SIZE: Size of a compressed public key.
# - UNCOMPRESSED_PUBLIC_KEY_SIZE: Size of an uncompressed public key.
# - PUBKEYHASH_BITS: Number of bits in a public key hash.
# - PUBKEYHASH_SIZE: Size of a public key hash in bytes.
# - DECODED_BASE58_ADDRESS_SIZE: Size of a decoded Base58 address.
# - P2PKH_PREFIX: Prefix for Pay-to-PubKey-Hash addresses.
# - P2SH_PREFIX: Prefix for Pay-to-Script-Hash addresses.
# - BASE58_ALPHABET: Alphabet used for Base58 encoding.
###
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
export DECODED_BASE58_ADDRESS_SIZE = 1 + PUBKEYHASH_SIZE + CHECKSUM_SIZE
export P2PKH_PREFIX = 0
export P2SH_PREFIX = 5
export BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

###
# Local Debugging functions:
# - debugging: Flag to enable or disable debugging.
# - debuggingIndent: Number of indentations for debugging output.
###
debugging = false
debuggingIndent = 1
###
# Logs the provided arguments if debugging is enabled.
#
# @param {...*} args - The arguments to log.
###
logIfDebugging = (args...) ->
  if debugging
    indent = '| '.repeat(debuggingIndent)
    console.log indent, ...args
  return

###
# Logs the entry of a function if debugging is enabled.
# @param {...*} args - The arguments to be logged.
###
logEnterIfDebugging = (args...) ->
  if debugging
    indent = '| '.repeat(debuggingIndent)
    console.log indent, ...args
    ++debuggingIndent
  return

###
# Logs the provided arguments and exits the process if debugging is enabled.
#
# @param {...*} args - The arguments to log.
###
logExitIfDebugging = (args...) ->
  if debugging
    indent = '| '.repeat(debuggingIndent)
    console.log indent, ...args
    --debuggingIndent
  return

###
# Checks if the given text is a valid Base58 encoded string.
# 
# @param {string} text - The text to be validated as Base58.
# @returns {boolean} - Returns true if the text is a valid Base58 encoded string, otherwise false.
###
export base58IsValid = (text) ->
  text.toString().match(/^[123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz]+$/) != null

###
# Checks if a given string is valid hex.
#
# @param {string} hex - The string to validate.
# @returns {boolean} - Returns true if the string is valid hex, otherwise false.
###
export hexIsValid = (hex) ->
  hex.toString().match(/^[0-9a-fA-F]+$/) != null

###
# Validates the checksum of the provided data.
#
# @param {String} data - The data for which the checksum needs to be validated.
# @return {Boolean} - Returns true if the checksum is valid, otherwise false.
###
export checksumIsValid = (data) ->
  logEnterIfDebugging "checksumIsValid: (data=#{data.toString('hex')})"

  check = data[-CHECKSUM_SIZE...]
  computed = checksum(data[...-CHECKSUM_SIZE])
  logIfDebugging "checksumIsValid: check=#{check.toString('hex')}, computed=#{computed.toString('hex')}"

  valid = check.compare(computed) == 0

  logExitIfDebugging "checksumIsValid: returning #{valid.toString()}"
  return valid

###
# Checks if the provided binary private key is valid.
# @param {String} key - The private key to validate.
# @returns {Boolean} - Returns true if the private key is valid, otherwise false.
###
privateKeyIsValid = (key) ->
  logEnterIfDebugging "privateKeyIsValid: (key=#{key.toString('hex')})"

  logExitIfDebugging "privateKeyIsValid: key.length=#{key.length}" if key.length != PRIVATE_KEY_SIZE
  return false if key.length != PRIVATE_KEY_SIZE

  logExitIfDebugging "privateKeyIsValid: key=#{key.toString('hex')}" if key.compare(MIN_PRIVATE_KEY) < 0 or key.compare(MAX_PRIVATE_KEY) > 0
  return false if key.compare(MIN_PRIVATE_KEY) < 0 or key.compare(MAX_PRIVATE_KEY) > 0

  logExitIfDebugging "privateKeyIsValid: returning true"
  return true

###
# Checks if the given hexadecimal string is a valid private key.
# 
# @param {string} hex - The hexadecimal string to validate.
# @returns {boolean} - Returns true if the hex string is a valid private key, otherwise false.
###
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

###
# Checks if the provided string is valid Wallet Import Format (WIF).
# 
# @param {string} wif - The data to be validated.
# @returns {boolean} - Returns true if the string is valid, otherwise false.
###
export wifIsValid = (wif) ->
  logEnterIfDebugging "wifIsValid: (wif=#{wif.toString()})"

  [ valid ] = decodedWif(wif)

  logExitIfDebugging "wifIsValid: returning #{valid.toString()}"
  return valid


###
# Checks if the provided public key is valid.
# @param {String} key - The public key to validate.
# @returns {Boolean} - Returns true if the public key is valid, otherwise false.
###
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

###
# Checks if the given string is a valid public key in hex.
# @param {string} hex - The string to validate.
# @returns {boolean} - Returns true if the string is a valid public key, otherwise false.
###
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

###
# Checks if the given data is a valid public key hash.
# @param {Buffer} hash - The data to validate.
# @returns {Boolean} - Returns true if the data is valid, otherwise false.
###
pubKeyHashIsValid = (hash) ->
  logEnterIfDebugging "pubKeyHashIsValid: (hash=#{hash.toString('hex')})"

  logExitIfDebugging "pubKeyHashIsValid: hash.length=#{hash.length}" if hash.length != PUBKEYHASH_SIZE
  return false if hash.length != PUBKEYHASH_SIZE

  logExitIfDebugging "pubKeyHashIsValid: returning true"
  return true
  logEnterIfDebugging "pubKeyHashIsValid: (hash=#{hash.toString('hex')})"

  logExitIfDebugging "pubKeyHashIsValid: hash.length=#{}{hash.length}" if hash.length != PUBKEYHASH_SIZE
  return false if hash.length != PUBKEYHASH_SIZE

  logExitIfDebugging "pubKeyHashIsValid: returning true"
  return true

###
# Checks if the given string is a valid public key hash in hex.
# 
# @param {string} hex - The hexadecimal string to validate.
# @returns {boolean} - Returns true if the string is a valid public key hash, otherwise false.
###
export hexIsValidPubkeyHash = (hex) ->
  logEnterIfDebugging "hexIsValidPubkeyHash: (hex=#{hex.toString()})"

  logExitIfDebugging "hexIsValidPubkeyHash: hexIsValid returned #{hexIsValid(hex)}" if not hexIsValid(hex) 
  return if not hexIsValid(hex)

  logExitIfDebugging "hexIsValidPubkeyHash: hex.length=#{hex.length}" if hex.length != PUBKEYHASH_SIZE * 2
  return false if hex.length != PUBKEYHASH_SIZE * 2 

  hash = Buffer.from(hex.toString(), 'hex')
  valid = pubKeyHashIsValid(hash)

  logExitIfDebugging "hexIsValidPubkeyHash: returning #{valid.toString()}"
  return valid


###
# Calculates the checksum of the given data.
# @param {Buffer} data - The data to calculate the checksum for.
# @returns {Buffer} The calculated checksum.
###
checksum = (data) ->
  logEnterIfDebugging "checksum: (data=#{data.toString('hex')})"

  # The checksum is the first 4 bytes of the double SHA-256 hash of the data.
  hash1 = Crypto.createHash('sha256').update(data).digest()
  hash2 = Crypto.createHash('sha256').update(hash1).digest()
  check = hash2[...CHECKSUM_SIZE]

  logExitIfDebugging "checksum: returning #{check.toString('hex')}"
  return check

###
# Encodes the given data using Base58Check encoding.
# @param {Buffer} data - The data to be encoded.
# @returns {String} The Base58Check encoded string.
###
base58Check = (data) ->
  logEnterIfDebugging "base58Check: (data=#{data.toString('hex')})"

  check = checksum(data)
  work = Buffer.concat([ data, check ])
  encoded = Buffer.from(Base58.encode(work))

  logExitIfDebugging "base58Check: returning [ #{encoded.toString()}, #{check.toString('hex')} ]"
  return [ encoded, check ]

###
# Generates a new secp256k1 private key.
# @returns {String} The generated private key.
###
export generatedPrivateKey = () ->
  key = Buffer.alloc(PRIVATE_KEY_SIZE)
  Crypto.randomFillSync(key)

  while key.compare(MIN_PRIVATE_KEY) < 0 or key.compare(MAX_PRIVATE_KEY) > 0
    Crypto.randomFillSync(key)

  return key

###
# Generates a new WIF-encoded secp256k1 private key.
# 
# @returns {String} The generated key.
###
export generatedWif = () ->
  [ encoded ] = encodedWif(generatedPrivateKey())
  return encoded

###
# Encodes a given private key into Wallet Import Format (WIF).
#
# @param {Buffer} key - The private key to be encoded.
# @param {boolean} [compressed=true] - Whether the public key should be compressed.
# @param {number} [prefix=0x80] - The prefix byte to use for the WIF encoding.
# @returns {string} The encoded WIF string.
###
export encodedWif = (key, compressed = true, prefix = 0x80) ->
  logEnterIfDebugging "encodedWif: (key=#{key.toString('hex')}, compressed=#{compressed.toString()}, prefix=#{prefix})"

  if compressed
    work = Buffer.concat([ Buffer.alloc(1, prefix), key, Buffer.alloc(1, 0x01) ])
  else
    work = Buffer.concat([ Buffer.alloc(1, prefix), key ])
  encoded = base58Check(work)

  logExitIfDebugging "encodedWif: returning #{encoded[0].toString()}"
  return encoded

###
# Decodes a Wallet Import Format (WIF) string into a private key.
# 
# @param {string} wif - The WIF string to decode.
# @returns {Object} - The decoded WIF information.
###
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

###
# Generates a public key from a given private key.
#
# @param {Buffer} privKey - The private key to generate the public key from.
# @param {Boolean} compressed - A flag indicating whether the public key should be compressed.
# @returns {String} The generated public key.
###
export publicKey = (privKey, compressed) ->
  logEnterIfDebugging "publicKey: (privKey=#{privKey.toString("hex")}, compressed=#{compressed.toString()}"

  ecdh = Crypto.createECDH('secp256k1')
  ecdh.setPrivateKey privKey
  key = ecdh.getPublicKey(null, if compressed then "compressed" else "uncompressed")

  logExitIfDebugging "publicKey: returning #{key.toString("hex")}"
  return key

###
# Generates a public key hash from the given public key.
# @param {String} pubKey - The public key to be hashed.
# @returns {String} The resulting public key hash.
###
export pubKeyHash = (pubKey) ->
  logEnterIfDebugging "pubKey: (pubKey=#{pubKey.toString('hex')})"

  hash1 = Crypto.createHash('sha256').update(pubKey).digest()
  hash2 = Crypto.createHash('ripemd160').update(hash1).digest()
  
  logExitIfDebugging "pubKeyHash: returning #{hash2.toString('hex')}"
  return hash2

###
# Generates a Base58Check encoded address from a given public key.
#
# @param {Buffer} pubKey - The public key to generate the address from.
# @param {number} [prefix=0] - The prefix to use for the address. Defaults to 0.
# @returns {string} - The Base58Check encoded address.
###
export base58Address = (pubKey, prefix = 0) ->
  logEnterIfDebugging "base58Address: (pubKey=#{pubKey.toString('hex')}, prefix=#{prefix})"

  hash = pubKeyHash(pubKey)
  [ encoded, check ] = base58EncodedAddress(hash, prefix)

  logExitIfDebugging "base58Address: returning [ #{encoded.toString()}, #{check.toString('hex')} ]"
  return [ encoded, check ]

###
# Encodes a given hash into a Base58Check encoded address with an optional prefix.
#
# @param {Buffer} hash - The hash to be encoded.
# @param {number} [prefix=0] - The prefix to be added to the hash before encoding.
# @returns {[string, Buffer]} - The Base58Check encoded address along with the checksum value.
###
export base58EncodedAddress = (hash, prefix = 0) ->
  logEnterIfDebugging "base58EncodedAddress: (hash=#{hash.toString('hex')}, prefix=#{prefix})"

  work = Buffer.concat([ Buffer.alloc(1, prefix), hash ])
  [ encoded, check ] = base58Check(work)

  logExitIfDebugging "base58EncodedAddress: returning [ #{encoded.toString()}, #{check.toString('hex')} ]"
  return [ encoded, check ]

###
Decodes a Base58 encoded Bitcoin address.

@param {String} addr - The Base58 encoded Bitcoin address to decode.
@returns {String} - The decoded Bitcoin address.
###
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

###
# Function to get the address type name based on the given prefix.
# @param {String} prefix - The prefix used to determine the address type name.
# @returns {String} The address type name corresponding to the given prefix.
###
export addressTypeName = (prefix) ->
  if prefix is 0x00
    'Bitcoin P2PKH'
  else if prefix is 0x05
    'Bitcoin P2SH'
#  else if prefix is 0xff
#    'Litecoin P2PKH'
#  else if prefix is 0xff
#    'Litecoin P2SH'
  else if prefix is 0x1e
    'Dogecoin'
  else
    null

###
# Checks if the given Bitcoin address is valid.
# @param {String} addr - The Bitcoin address to validate.
# @returns {Boolean} - Returns true if the address is valid, otherwise false.
###
export addressIsValid = (addr) ->
  [valid] = decodedBase58Address(addr)
  return valid