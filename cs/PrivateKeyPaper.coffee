`
import { generatedPrivateKey, encodedWif, decodedWif, base58IsValid, hexIsValidPrivateKey, wifIsValid, checksumIsValid} from './Common'
import { PRIVATE_KEY_SIZE, DECODED_COMPRESSED_PRIVATE_KEY_SIZE, DECODED_UNCOMPRESSED_PRIVATE_KEY_SIZE, MIN_PRIVATE_KEY, MAX_PRIVATE_KEY } from './Common'
import ModifiableText from './ModifiableText'

import Button from '@material-ui/core/Button'
import Paper from '@material-ui/core/Paper'
import React, { Component } from 'react'
import Typography from '@material-ui/core/Typography'
`

Base58 = require "base-58"

class PrivateKeyPaper extends Component
  constructor: (props) ->
    super props
    privateKey = generatedPrivateKey()
    prefix = 0x80
    [ compressedWif, compressedChecksum ] = encodedWif(prefix, privateKey, true)
    [ uncompressedWif, uncompressedChecksum ] = encodedWif(prefix, privateKey, false)
    @state = {
      privateKey
      compressedWif
      compressedChecksum
      uncompressedWif
      uncompressedChecksum
      prefix
      compressed: true
      validator: {
        wif: compressedWif
        valid: true
        details: "Valid"
      }
    }
    return

  handlePrivateKeyHexChange: (value) =>
    valueBuf = Buffer.from(value)
    if not hexIsValidPrivateKey(valueBuf)
      @setState {
        privateKey: null
        compressedWif: null
        compressedChecksum: null
        uncompressedWif: null
        uncompressedChecksum: null
        prefix: null
        compressed: null
      }
      return

    privateKey = Buffer.from(value, 'hex')
    [ compressedWif, compressedChecksum ] = encodedWif(0x80, privateKey, true)
    [ uncompressedWif, uncompressedChecksum ] = encodedWif(0x80, privateKey, false)
    @setState {
      privateKey
      compressedWif
      compressedChecksum
      uncompressedWif
      uncompressedChecksum
      prefix: 0x80
      compressed: true
    }
    return

  handlePrivateKeyWifChange: (value) =>
    valueBuf = Buffer.from(value)
    [ valid, compressed, prefix, privateKey ] = decodedWif(valueBuf)
    if not valid
      @setState {
        privateKey: null
        compressedWif: null
        compressedChecksum: null
        uncompressedWif: null
        uncompressedChecksum: null
        prefix: null
        compressed: null
      }
      return

    [ compressedWif, compressedChecksum ] = encodedWif(prefix, privateKey, true)
    [ uncompressedWif, uncompressedChecksum ] = encodedWif(prefix, privateKey, false)
    @setState {
      privateKey
      compressedWif
      compressedChecksum
      uncompressedWif
      uncompressedChecksum
      prefix
      compressed
    }

    return      

  handleValidatorChange: (value) =>
    valueBuf = Buffer.from(value)
    # Check characters before attempting to decode
    if not base58IsValid(valueBuf)
      @setState { validator: { wif: valueBuf, valid: false, details: "Invalid characters" }}
      return

    work = Buffer.from(Base58.decode(valueBuf))

    if work.length < DECODED_UNCOMPRESSED_PRIVATE_KEY_SIZE
      @setState { validator: { wif: valueBuf, valid: false, details: "Missing characters" }}
      return

    if work.length > DECODED_COMPRESSED_PRIVATE_KEY_SIZE
      @setState { validator: { wif: valueBuf, valid: false, details: "Extra characters" }}
      return

    if not checksumIsValid(work)
      @setState { validator: { wif: valueBuf, valid: false, details: "Checksum mismatch" }}
      return
    
    if work[0] != 0x80
      @setState { validator: { wif: valueBuf, valid: false, details: "Invalid prefix" }}
      return
    
    privateKey = work[1...1 + PRIVATE_KEY_SIZE]
    if privateKey.compare(MIN_PRIVATE_KEY) < 0 or privateKey.compare(MAX_PRIVATE_KEY) > 0
      @setState { validator: { wif: valueBuf, valid: false, details: "Private key is outside of the valid range" }}
      return

    if work.length == DECODED_COMPRESSED_PRIVATE_KEY_SIZE and work[1 + PRIVATE_KEY_SIZE] != 1
      @setState { validator: { wif: valueBuf, valid: false, details: "Invalid compressed flag value" }}
      return

    @setState { validator: { wif: valueBuf, valid: true, details: "Valid" }}
    return

  render: ->
    <div>
      <WifEncodingPaper
        privateKey={@state.privateKey}
        uncompressedChecksum={@state.uncompressedChecksum}
        uncompressedWif={@state.uncompressedWif}
        compressedChecksum={@state.compressedChecksum}
        compressedWif={@state.compressedWif}
        privateKeyValidator={hexIsValidPrivateKey}
        onChange={@handlePrivateKeyHexChange}
      />
      <WifDecodingPaper
        privateKeyWif={if @state.compressed then @state.compressedWif else @state.uncompressedWif}
        prefix={@state.prefix}
        privateKey={@state.privateKey}
        compressed={@state.compressed}
        checksum={if @state.compressed then @state.compressedChecksum else @state.uncompressedChecksum}
        wifValidator={wifIsValid}
        onChange={@handlePrivateKeyWifChange}
      />
      <WifValidatorPaper
        privateKeyWif={@state.validator.wif}
        valid={@state.validator.valid}
        details={@state.validator.details}
        onChange={@handleValidatorChange}
      />
    </div>

WifEncodingPaper = (props) ->
  { privateKey, uncompressedChecksum, uncompressedWif, compressedChecksum, compressedWif, privateKeyValidator, onChange } = props

  <Paper variant='outlined'>
    <Typography variant="h4">WIF Encoding</Typography>
    <div style={{margin: "1%"}}>
      <Typography variant="h5">Private Key (hex):</Typography>
      <div style={{margin: "1%"}}>
        <Button variant="contained" color="primary" onClick={() => onChange(generatedPrivateKey().toString('hex'))}>Random</Button>
        <ModifiableText
          value={privateKey.toString('hex')}
          validator={privateKeyValidator}
          helperText="invalid private key"
          onChange={onChange}
        />
      </div>
      <Typography variant="h5">Uncompressed:</Typography>
      <div style={{margin: "1%"}}>
        <Typography variant="h6">Checksum:</Typography>
        <div style={{margin: "1%"}}>
          <span class="code">80&nbsp;|&nbsp;{privateKey.toString('hex')}</span>
          &nbsp;&nbsp;⟹&nbsp;&nbsp;
          SHA-256(SHA-256())
          &nbsp;&nbsp;⟹&nbsp;&nbsp;
          <span class="code"><b>{uncompressedChecksum.toString('hex')}</b></span>
        </div>
        <Typography variant="h6">WIF:</Typography>
        <div style={{margin: "1%"}}>
          <span class="code">80&nbsp;|&nbsp;{privateKey.toString('hex')}&nbsp;|&nbsp;{uncompressedChecksum.toString('hex')}</span>
          &nbsp;&nbsp;⟹&nbsp;&nbsp;
          Base58()
          &nbsp;&nbsp;⟹&nbsp;&nbsp;
          <b>{uncompressedWif.toString()}</b>
        </div>
      </div>
      <Typography variant="h5">Compressed:</Typography>
      <div style={{margin: "1%"}}>
        <Typography variant="h6">Checksum:</Typography>
        <div style={{margin: "1%"}}>
          <span class="code">80&nbsp;|&nbsp;{privateKey.toString('hex')}&nbsp;|&nbsp;01</span>
          &nbsp;&nbsp;⟹&nbsp;&nbsp;
          SHA-256(SHA-256())
          &nbsp;&nbsp;⟹&nbsp;&nbsp;
          <span class="code"><b>{compressedChecksum.toString('hex')}</b></span>
        </div>
        <Typography variant="h6">WIF:</Typography>
        <div style={{margin: "1%"}}>
          <span class="code"> 80&nbsp;|&nbsp;{privateKey.toString('hex')}&nbsp;|&nbsp;01&nbsp;|&nbsp;{compressedChecksum.toString('hex')}</span>
          &nbsp;&nbsp;⟹&nbsp;&nbsp;
          Base58()
          &nbsp;&nbsp;⟹&nbsp;&nbsp;
          <b>{compressedWif.toString()}</b>
        </div>
      </div>
    </div>
  </Paper>

WifDecodingPaper = (props) ->
  { privateKeyWif, prefix, privateKey, compressed, checksum, wifValidator, onChange } = props
  <Paper variant='outlined'>
    <Typography variant="h4">WIF Decoding</Typography>
    <div style={{margin: "1%"}}>
      <Typography variant="h6">Private Key (WIF):</Typography>
      <div style={{margin: "1%"}}>
        <ModifiableText
          value={privateKeyWif}
          validator={wifValidator}
          helperText="invalid private key"
          onChange={onChange}
        />
      </div>
      <p>Prefix:&nbsp;&nbsp;<b><span class="code">{prefix.toString(16)}</span></b></p>
      <p>Key:&nbsp;&nbsp;<b><span class="code">{privateKey.toString('hex')}</span></b></p>
      <p>Compressed:&nbsp;&nbsp;<b><span class="code">{compressed.toString()}</span></b></p>
      <p>Checksum:&nbsp;&nbsp;<b><span class="code">{checksum.toString('hex')}</span></b></p>
    </div>
  </Paper>

WifValidatorPaper = (props) ->
  { privateKeyWif, valid, details, onChange } = props
  <Paper variant='outlined'>
    <Typography variant="h4">WIF Validator</Typography>
    <div style={{margin: "1%"}}>
      <Typography variant="h6">Private Key (WIF):</Typography>
      <div style={{margin: "1%"}}>
        <ModifiableText
          value={privateKeyWif}
          onChange={onChange}
        />
      </div>
      <b>
      {
        if valid
          <span style={{color: "green"}}>{details}</span>
        else
          <span style={{color: "red"}}>{details}</span>
      }
      </b>
    </div>
  </Paper>

export default PrivateKeyPaper
