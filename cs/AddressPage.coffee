`
import { base58IsValid, checksumIsValid, hexIsValidPrivateKey, hexIsValidPublicKey, hexIsValidPubkeyHash } from './Common'
import { addressIsValid, wifIsValid, base58Address, generatedWif, encodedWif, decodedWif, publicKey } from './Common'
import { base58EncodedAddress, pubKeyHash, decodedBase58Address, addressTypeName } from './Common'
import { P2PKH_PREFIX, P2SH_PREFIX, DECODED_BASE58_ADDRESS_SIZE } from './Common'
import ModifiableText from './ModifiableText'

import Button from '@material-ui/core/Button'
import Paper from '@material-ui/core/Paper'
import React, { Component } from 'react'
import Typography from '@material-ui/core/Typography'
`

Base58 = require "base-58"

#.my-card-content {
#  padding: 16px;
#}
#.my-card {
#  height: 100px;
#  width: 300px;
#}

class AddressPage extends Component
  constructor: (props) ->
    super props

    wif = generatedWif()
    [ valid, privKey, compressed ] = decodedWif(wif)
    pubKey = publicKey(privKey, compressed)
    hash = pubKeyHash(pubKey)
    p2pkh = {}
    [ p2pkh.address, p2pkh.check ] = base58Address(pubKey, P2PKH_PREFIX)
    p2sh = {}
    [ p2sh.address, p2sh.check ] = base58Address(pubKey, P2SH_PREFIX)

    @state = {
      wif
      privateKey: privKey
      compressed
      publicKey: pubKey
      pubKeyHash: hash
      p2pkh
      p2sh
      decoder:
        prefix: p2pkh.prefix
        check: p2pkh.check
      validator: {
        address: p2pkh.address
        valid
        details: "Valid"
      }
    }

  handleWifChange: (value) =>
    valueBuf = Buffer.from(value)
    [ valid, privKey, compressed ] = decodedWif(valueBuf)
    if not valid
      @setState {
        wif: valueBuf
        privateKey: null
        compressed: null
        publicKey: null
        pubKeyHash: null
        p2pkh:
          check: null
          address: null
        p2sh:
          check: null
          address: null
        decoder:
          prefix: null
          check: null
        validator:
          address: null
          valid: false
          details: null
      }
      return

    pubKey = publicKey(privKey, compressed)
    hash = pubKeyHash(pubKey)
    p2pkh = {}
    [ p2pkh.address, p2pkh.check ] = base58Address(pubKey, P2PKH_PREFIX)
    p2sh = {}
    [ p2sh.address, p2sh.check ] = base58Address(pubKey, P2SH_PREFIX)

    @setState {
      wif: valueBuf
      privateKey: privKey
      compressed
      publicKey: pubKey
      pubKeyHash: hash
      p2pkh
      p2sh
      decoder:
        prefix: p2pkh.prefix
        check: p2pkh.check
      validator:
        address: p2pkh.address
        valid: true
        details: "Valid"
    }
    return

  handlePrivateKeyChange: (value) =>
    valueBuf = Buffer.from(value)
    if not hexIsValidPrivateKey(valueBuf)
      @setState {
        wif: null
        privateKey: null
        compressed: null
        publicKey: null
        pubKeyHash: null
        p2pkh:
          check: null
          address: null
        p2sh:
          check: null
          address: null
        decoder:
          prefix: null
          check: null
        validator:
          address: null
          valid: false
          details: null
      }
      return

    privKey = Buffer.from(value, 'hex')
    [ compressedWif ] = encodedWif(privKey, true, 0x80)
    pubKey = publicKey(privKey, true)
    hash = pubKeyHash(pubKey)
    p2pkh = {}
    p2pkh.prefix = P2PKH_PREFIX
    [ p2pkh.address, p2pkh.check ] = base58Address(pubKey, P2PKH_PREFIX)
    p2sh = {}
    p2sh.prefix = P2SH_PREFIX
    [ p2sh.address, p2sh.check ] = base58Address(pubKey, P2SH_PREFIX)

    @setState {
      wif: compressedWif
      privateKey: privKey
      compressed: true
      publicKey: pubKey
      pubKeyHash: hash
      p2pkh
      p2sh
      decoder:
        prefix: p2pkh.prefix
        check: p2pkh.check
      validator:
        address: p2pkh.address
        valid: true
        details: "Valid"
    }
    return

  handlePublicKeyChange: (value) =>
    valueBuf = Buffer.from(value)
    if not hexIsValidPublicKey(valueBuf)
      @setState {
        wif: null
        privateKey: null
        compressed: null
        publicKey: null
        pubKeyHash: null
        p2pkh:
          check: null
          address: null
        p2sh:
          check: null
          address: null
        decoder:
          prefix: null
          check: null
        validator:
          address: null
          valid: false
          details: null
      }
      return

    pubKey = Buffer.from(value, 'hex')
    hash = pubKeyHash(pubKey)
    p2pkh = {}
    p2pkh.prefix = P2PKH_PREFIX
    [ p2pkh.address, p2pkh.check ] = base58Address(pubKey, P2PKH_PREFIX)
    p2sh = {}
    p2sh.prefix = P2SH_PREFIX
    [ p2sh.address, p2sh.check ] = base58Address(pubKey, P2SH_PREFIX)

    @setState {
      wif: null
      privateKey: null
      compressed: null
      publicKey: pubKey
      pubKeyHash: hash
      p2pkh
      p2sh
      decoder:
        prefix: p2pkh.prefix
        check: p2pkh.check
      validator:
        address: p2pkh.address
        valid: true
        details: "Valid"
    }
    return

  handlePubKeyHashChange: (value) =>
    valueBuf = Buffer.from(value)
    if not hexIsValidPubkeyHash(valueBuf)
      @setState {
        wif: null
        privateKey: null
        compressed: null
        publicKey: null
        pubKeyHash: null
        p2pkh:
          check: null
          address: null
        p2sh:
          check: null
          address: null
        decoder:
          prefix: null
          check: null
        validator:
          address: null
          valid: false
          details: null
      }
      return
    hash = Buffer.from(value, 'hex')
    p2pkh = {}
    p2pkh.prefix = P2PKH_PREFIX
    [ p2pkh.address, p2pkh.check ] = base58EncodedAddress(hash, P2PKH_PREFIX)
    p2sh = {}
    p2sh.prefix = P2SH_PREFIX
    [ p2sh.address, p2sh.check ] = base58EncodedAddress(hash, P2SH_PREFIX)
    @setState {
      wif: null
      privateKey: null
      compressed: null
      publicKey: null
      pubKeyHash: hash
      p2pkh
      p2sh
      decoder:
        prefix: p2pkh.prefix
        check: p2pkh.check
      validator:
        address: p2pkh.address
        valid: true
        details: "Valid"
    }
    return

  handleDecoderChange: (value) =>
    valueBuf = Buffer.from(value)
    [valid, hash, prefix, check ] = decodedBase58Address(valueBuf)

    if not valid
      @setState {
        wif: null
        privateKey: null
        compressed: null
        publicKey: null
        pubKeyHash: null
        p2pkh:
          check: null
          address: null
        p2sh:
          check: null
          address: null
        decoder:
          prefix: null
          check: null
        validator:
          address: null
          valid: false
          details: null
      }
      return
    @setState {
      wif: null
      privateKey: null
      compressed: null
      publicKey: null
      pubKeyHash: hash
      p2pkh:
        check: null
        address: null
      p2sh:
        check: null
        address: null
      decoder:
        prefix: prefix
        check: check
      validator:
        address: valueBuf
        valid: true
        details: "Valid"
    }
    return

  handleValidatorChange: (value) =>
    valueBuf = Buffer.from(value)
    # Check characters before attempting to decode
    if not base58IsValid(valueBuf)
      @setState { validator: { address: valueBuf, valid: false, details: "Invalid characters" }}
      return

    work = Buffer.from(Base58.decode(value))

    if work.length < DECODED_BASE58_ADDRESS_SIZE
      @setState { validator: { address: valueBuf, valid: false, details: "Missing characters" }}
      return

    if work.length > DECODED_BASE58_ADDRESS_SIZE
      @setState { validator: { address: valueBuf, valid: false, details: "Extra characters" }}
      return

    if not checksumIsValid(work)
      @setState { validator: { address: valueBuf, valid: false, details: "Checksum mismatch" }}
      return
    
    if addressTypeName(work[0]) is null
      @setState { validator: { address: valueBuf, valid: false, details: "Invalid prefix" }}
      return
    
    @setState { validator: { wif: valueBuf, valid: true, details: "Valid" }}
    return

  render: ->
    <div>
      <DerivationPaper
        wif={@state.wif}
        privKey={@state.privateKey}
        compressed={@state.compressed}
        pubKey={@state.publicKey}
        hash={@state.pubKeyHash}
        p2pkh={@state.p2pkh}
        p2sh={@state.p2sh}
        onWifChange={@handleWifChange}
        onPrivateKeyChange={@handlePrivateKeyChange}
        onPublicKeyChange={@handlePublicKeyChange}
        onPubKeyHashChange={@handlePubKeyHashChange}
      />
      <DecodingPaper
        address={@state.decoder.address}
        prefix={@state.prefix}
        hash={@state.pubKeyHash}
        check={@state.decoder.check}
        onChange={@handleDecoderChange}
      />
      <ValidationPaper
        address={@state.validator.address}
        valid={@state.validator.valid}
        details={@state.validator.details}
        onChange={@handleValidatorChange}
      />
    </div>

DerivationPaper = (props) ->
  { wif, privKey, compressed, pubKey, hash, p2pkh, p2sh, onWifChange, onPrivateKeyChange, onPublicKeyChange, onPubKeyHashChange } = props
  <Paper>
    <Typography variant="h4">Derivation</Typography>
    <div style={{margin: "1%"}}>
      <Button variant="contained" color="primary" onClick={() => onWifChange(generatedWif())}>Random</Button>
      <ModifiableText
        value={if wif? then wif.toString() else ''}
        validator={wifIsValid}
        label="Private Key (WIF)"
        helperText="invalid private key"
        onChange={onWifChange}
      />
      <ModifiableText
        value={if privKey? then privKey.toString('hex') else ''}
        validator={hexIsValidPrivateKey}
        label="Private Key (hex)"
        helperText="invalid private key"
        onChange={onPrivateKeyChange}
      />
      Compressed  :&nbsp;&nbsp;<b><span class="code">{if compressed? then compressed.toString() else ''}</span></b><br/>
      <ModifiableText
        value={if pubKey? then pubKey.toString('hex') else ''}
        validator={hexIsValidPublicKey}
        label="Public Key (hex)"
        helperText="invalid private key"
        onChange={onPublicKeyChange}
      />
      <ModifiableText
        value={if hash? then hash.toString('hex') else ''}
        validator={hexIsValidPubkeyHash}
        label="PubKeyHash"
        helperText="invalid pubkey hash"
        onChange={onPubKeyHashChange}
      />
      <br/>
      <Typography variant="h5">P2PKH</Typography>
      <div style={{margin: "1%"}}>
        <Typography variant="h6">Checksum</Typography>
        <div style={{margin: "1%"}}>
          <span class="code">00&nbsp;{if hash? then hash.toString('hex') else ''}</span>
          &nbsp;&nbsp;⟹&nbsp;&nbsp;
          SHA-256(SHA-256())
          &nbsp;&nbsp;⟹&nbsp;&nbsp;
          <b><span class="code">{if p2pkh? then p2pkh.check.toString('hex') else ''}</span></b>
        </div>
        <Typography variant="h6">Address</Typography>
        <div style={{margin: "1%"}}>
          <span class="code">00&nbsp;{if hash? then hash.toString('hex') else ''}&nbsp;{if p2pkh? then p2pkh.check.toString('hex') else ''}</span>
          &nbsp;&nbsp;⟹&nbsp;&nbsp;
          Base58()
          &nbsp;&nbsp;⟹&nbsp;&nbsp;
          <b><span class="code">{if p2pkh? then p2pkh.address.toString() else ''}</span></b>
        </div>
      </div>
      <Typography variant="h5">P2SH</Typography>
      <div style={{margin: "1%"}}>
        <Typography variant="h6">Checksum</Typography>
        <div style={{margin: "1%"}}>
          <span class="code">05&nbsp;{if hash? then hash.toString('hex') else ''}</span>
          &nbsp;&nbsp;⟹&nbsp;&nbsp;
          SHA-256(SHA-256())
          &nbsp;&nbsp;⟹&nbsp;&nbsp;
          <b><span class="code">{if p2sh? then p2sh.check.toString('hex')else ''}</span></b>
        </div>
        <Typography variant="h6">Address</Typography>
        <div style={{margin: "1%"}}>
          <span class="code">05&nbsp;{if hash? then hash.toString('hex') else ''}&nbsp;{if p2sh? then p2sh.check.toString('hex') else ''}</span>
          &nbsp;&nbsp;⟹&nbsp;&nbsp;
          Base58()
          &nbsp;&nbsp;⟹&nbsp;&nbsp;
          <b><span class="code">{if p2sh? then p2sh.address.toString() else ''}</span></b>
        </div>
      </div>
      <Typography variant="h5">Bech32</Typography>
      <div style={{margin: "1%"}}>
      </div>
    </div>
  </Paper>

DecodingPaper = (props) ->
  { address, prefix, hash, check, onChange } = props
  <Paper>
    <Typography variant="h4">Decoding</Typography>
    <div style={{margin: "1%"}}>
      <ModifiableText
        value={address}
        label="Address"
        validator={addressIsValid}
        helperText="invalid address"
        onChange={onChange}
      />
      Prefix:&nbsp;&nbsp;<b><span class="code">{if prefix? then prefix.toString(16) else ''} ({if prefix? then addressTypeName(prefix)} else '')</span></b><br/>
      PubKeyHash:&nbsp;&nbsp;<b><span class="code">{if hash? then hash.toString('hex') else ''}</span></b><br/>
      Checksum:&nbsp;&nbsp;<b><span class="code">{if check? then check.toString('hex') else ''}</span></b><br/>
    </div>
  </Paper>


ValidationPaper = (props) ->
  { address, valid, details, onChange } = props
  <Paper>
    <Typography variant="h4">Validation</Typography>
    <div style={{margin: "1%"}}>
      <ModifiableText
        value={address.toString()}
        label="Address"
        onChange={onChange}
      />
      <b>
      {
        if valid
          <span style={{color: "green"}}>{if details? then details else ''}</span>
        else
          <span style={{color: "red"}}>{if details? then details else ''}</span>
      }
      </b>
    </div>
  </Paper>

export default AddressPage
