`
import { publicKey, pubKeyHash, P2PKH_PREFIX, BASE58_ALPHABET } from './Common'
import { base58Address, addressTypeName } from './Common'
import ModifiableText from './ModifiableText'

import Button from '@material-ui/core/Button'
import Paper from '@material-ui/core/Paper'
import React, { Component } from 'react'
import Typography from '@material-ui/core/Typography'
`

Crypto = require "crypto"

randomInt = (min, max) ->
  buf = Crypto.randomBytes(8)
  high = buf.readUInt32BE(0)
  low = buf.readUInt32BE(4)
  return Math.floor(((high * 2**32 + low) / 2**64) * (max - min) + min)

#.my-card-content {
#  padding: 16px;
#}
#.my-card {
#  height: 100px;
#  width: 300px;
#}

###
# Generates a mini key.
# @returns {String} The generated mini key.
###
generatedMiniKey =  () ->
  valid = false
  while not valid
    miniKey = randomMiniKey()
    [valid, details] = validateMiniKey(miniKey)
  return miniKey

###
# Generates a random mini key candidate.
# @returns {String} - The candidate mini key
###
randomMiniKey = () ->
    miniKey = 'S'
    for i in [1..29]
        miniKey += BASE58_ALPHABET[randomInt(0, BASE58_ALPHABET.length)]
    return miniKey

###
# Decodes a mini private key into a full private key.
# @param {String} miniKey - The mini private key to be decoded.
# @returns {Buffer (or null), String} - The decoded full private key and a message.
###
decodedMiniKey =  (miniKey) ->
  [valid, details] = validateMiniKey(miniKey)
  if valid
      hash = Crypto.createHash('sha256').update(miniKey).digest()
      [hash, details]
  else
      [null, details]

###
# Validates a mini private key.
# @param {Buffer} miniKey - The mini private key to validate.
# @returns {Boolean} - Returns true if the mini key is valid, otherwise false.
###
validateMiniKey =  (miniKey) ->
  # Mini key is 30 characters long
  if miniKey.length != 30
      return [false, "Invalid: Mini key must be 30 characters long"]
  # First character is 'S'
  if miniKey[0] != 'S'
      return [false, "Invalid: First character must be 'S'"]
  # All other characters are in the base58 alphabet
  for c in miniKey[1..]
    if BASE58_ALPHABET.indexOf(c) is -1
      return [false, "Invalid: All characters must be in the base58 alphabet"]
  # The first byte of the SHA-256 hash of the mini key appended with '?' must be 0
  hash = Crypto.createHash('sha256').update(miniKey + '?').digest()
  if hash[0] !=  0
      return [false, "Invalid: Check failed"]
  
  return [true, "Valid"]

class MiniKeyPage extends Component
  constructor: (props) ->
    super props
    miniKey = generatedMiniKey()
    [ prv, details ] = decodedMiniKey(miniKey)
    if prv?
      pub = publicKey(prv, false)
      hash = pubKeyHash(pub)
      p2pkh = {}
      [ p2pkh.address, p2pkh.check ] = base58Address(pub, P2PKH_PREFIX)

      @state = {
        miniKey
        privateKey: prv
        publicKey: pub
        pubKeyHash: hash
        address: p2pkh.address
        valid: true
        details
      }
    else
      @state = {
        miniKey
        privateKey: null
        publicKey: null
        pubKeyHash: null
        address: null
        valid: false
        details
      }
    return

  handleMiniKeyChange: (value) =>
    [ prv, details ] = decodedMiniKey(value)
    if prv?
      pub = publicKey(prv, false)
      hash = pubKeyHash(pub)
      p2pkh = {}
      [ p2pkh.address, p2pkh.check ] = base58Address(pub, P2PKH_PREFIX)
      @setState {
        miniKey: value
        privateKey: prv
        publicKey: pub
        pubKeyHash: hash
        address: p2pkh.address
        valid: true
        details
      }
    else
      @setState {
          miniKey: value
          privateKey: null
          publicKey: null
          pubKeyHash: null
          address: null
          valid: false
          details
      }
    return

  render: ->
    <DerivationPaper
      miniKey={@state.miniKey}
      privKey={@state.privateKey}
      pubKey={@state.publicKey}
      hash={@state.pubKeyHash}
      address={@state.address}
      valid={@state.valid}
      details={@state.details}
      onMiniKeyChange={@handleMiniKeyChange}
    />

DerivationPaper = (props) ->
  { miniKey, privKey, pubKey, hash, address, valid, details, onMiniKeyChange } = props
  <Paper>
    <Typography variant="h4">Mini Key Address Derivation</Typography>
    <div style={{margin: "1%"}}>
      <Button variant="contained" color="primary" onClick={() => onMiniKeyChange(generatedMiniKey())}>Random</Button>
      <ModifiableText
        value={if miniKey? then miniKey else ''}
        label="Mini Key"
        helperText="Enter a mini key"
        onChange={onMiniKeyChange}
      />
      Private Key:&nbsp;&nbsp;<b><span className="code">{if privKey? then privKey.toString('hex') else ''}</span></b><br/>
      Public Key:&nbsp;&nbsp;<b><span className="code">{if pubKey? then pubKey.toString('hex') else ''}</span></b><br/>
      PubKeyHash:&nbsp;&nbsp;<b><span className="code">{if hash? then hash.toString('hex') else ''}</span></b><br/>
      Address:&nbsp;&nbsp;<b><span className="code">{if address? then address.toString() else ''}</span></b><br/>
      <b>
      {
        if valid
          <span style={{color: "green"}}>{if details? then details else ''}</span>
        else
          <span style={{color: "red"}}>{if details? then details else ''}</span>
      }
      </b><br/>
    </div>
  </Paper>

export default MiniKeyPage
