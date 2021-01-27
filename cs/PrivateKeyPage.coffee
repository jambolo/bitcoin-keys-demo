`
import { base58IsValid, checksumIsValid, decodedWif, encodedWif, generatedPrivateKey, hexIsValidPrivateKey, wifIsValid } from './Common'
import { DECODED_COMPRESSED_PRIVATE_KEY_SIZE, DECODED_UNCOMPRESSED_PRIVATE_KEY_SIZE, MAX_PRIVATE_KEY, MIN_PRIVATE_KEY, PRIVATE_KEY_SIZE } from './Common'
import ModifiableText from './ModifiableText'

import Button from '@material-ui/core/Button'
import Paper from '@material-ui/core/Paper'
import React, { Component } from 'react'
import Typography from '@material-ui/core/Typography'
`

Base58 = require "base-58"

class PrivateKeyPage extends Component
  constructor: (props) ->
    super props
    privKey = generatedPrivateKey()
    prefix = 0x80
    [ compressedWif, compressedChecksum ] = encodedWif(privKey, true, prefix)
    [ uncompressedWif, uncompressedChecksum ] = encodedWif(privKey, false, prefix)
    @state = {
      privKey
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
        privKey: null
        compressedWif: null
        compressedChecksum: null
        uncompressedWif: null
        uncompressedChecksum: null
        prefix: null
        compressed: null
      }
      return

    privKey = Buffer.from(value, 'hex')
    [ compressedWif, compressedChecksum ] = encodedWif(privKey, true, 0x80)
    [ uncompressedWif, uncompressedChecksum ] = encodedWif(privKey, false, 0x80)
    @setState {
      privKey
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
    [ valid, privKey, compressed, check, prefix ] = decodedWif(valueBuf)
    if not valid
      @setState {
        privKey: null
        compressedWif: null
        compressedChecksum: null
        uncompressedWif: null
        uncompressedChecksum: null
        prefix: null
        compressed: null
      }
      return

    [ compressedWif, compressedChecksum ] = encodedWif(privKey, true, prefix)
    [ uncompressedWif, uncompressedChecksum ] = encodedWif(privKey, false, prefix)
    @setState {
      privKey
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

    work = Buffer.from(Base58.decode(valueBuf.toString()))

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
    
    privKey = work[1...1 + PRIVATE_KEY_SIZE]
    if privKey.compare(MIN_PRIVATE_KEY) < 0 or privKey.compare(MAX_PRIVATE_KEY) > 0
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
        privKey={@state.privKey}
        uncompressedChecksum={@state.uncompressedChecksum}
        uncompressedWif={@state.uncompressedWif}
        compressedChecksum={@state.compressedChecksum}
        compressedWif={@state.compressedWif}
        privateKeyValidator={hexIsValidPrivateKey}
        onChange={@handlePrivateKeyHexChange}
      />
      <WifDecodingPaper
        wif={if @state.compressed then @state.compressedWif else @state.uncompressedWif}
        prefix={@state.prefix}
        privKey={@state.privKey}
        compressed={@state.compressed}
        checksum={if @state.compressed then @state.compressedChecksum else @state.uncompressedChecksum}
        wifValidator={wifIsValid}
        onChange={@handlePrivateKeyWifChange}
      />
      <WifValidatorPaper
        wif={@state.validator.wif}
        valid={@state.validator.valid}
        details={@state.validator.details}
        onChange={@handleValidatorChange}
      />
    </div>

WifEncodingPaper = (props) ->
  { privKey, uncompressedChecksum, uncompressedWif, compressedChecksum, compressedWif, privateKeyValidator, onChange } = props

  <Paper>
    <Typography variant="h4">WIF Encoding</Typography>
    <div style={{margin: "1%"}}>
      <Button variant="contained" color="primary" onClick={() => onChange(generatedPrivateKey().toString('hex'))}>Random</Button>
      <ModifiableText
        value={privKey.toString('hex')}
        label="Private Key (hex)"
        validator={privateKeyValidator}
        helperText="invalid private key"
        onChange={onChange}
      />
      <Typography variant="h5">Uncompressed:</Typography>
      <div style={{margin: "1%"}}>
        <Typography variant="h6">Checksum:</Typography>
        <div style={{margin: "1%"}}>
          <span class="code">80&nbsp;{privKey.toString('hex')}</span>
          &nbsp;&nbsp;⟹&nbsp;&nbsp;
          SHA-256(SHA-256())
          &nbsp;&nbsp;⟹&nbsp;&nbsp;
          <span class="code"><b>{uncompressedChecksum.toString('hex')}</b></span>
        </div>
        <Typography variant="h6">WIF:</Typography>
        <div style={{margin: "1%"}}>
          <span class="code">80&nbsp;{privKey.toString('hex')}&nbsp;{uncompressedChecksum.toString('hex')}</span>
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
          <span class="code">80&nbsp;{privKey.toString('hex')}&nbsp;01</span>
          &nbsp;&nbsp;⟹&nbsp;&nbsp;
          SHA-256(SHA-256())
          &nbsp;&nbsp;⟹&nbsp;&nbsp;
          <span class="code"><b>{compressedChecksum.toString('hex')}</b></span>
        </div>
        <Typography variant="h6">WIF:</Typography>
        <div style={{margin: "1%"}}>
          <span class="code"> 80&nbsp;{privKey.toString('hex')}&nbsp;01&nbsp;{compressedChecksum.toString('hex')}</span>
          &nbsp;&nbsp;⟹&nbsp;&nbsp;
          Base58()
          &nbsp;&nbsp;⟹&nbsp;&nbsp;
          <b>{compressedWif.toString()}</b>
        </div>
      </div>
    </div>
  </Paper>

WifDecodingPaper = (props) ->
  { wif, prefix, privKey, compressed, checksum, wifValidator, onChange } = props
  <Paper>
    <Typography variant="h4">WIF Decoding</Typography>
    <div style={{margin: "1%"}}>
      <ModifiableText
        value={wif}
        label="Private Key (WIF)"
        validator={wifValidator}
        helperText="invalid private key"
        onChange={onChange}
      />
      Prefix:&nbsp;&nbsp;<b><span class="code">{prefix.toString(16)}</span></b><br/>
      Key:&nbsp;&nbsp;<b><span class="code">{privKey.toString('hex')}</span></b><br/>
      Compressed:&nbsp;&nbsp;<b><span class="code">{compressed.toString()}</span></b><br/>
      Checksum:&nbsp;&nbsp;<b><span class="code">{checksum.toString('hex')}</span></b><br/>
    </div>
  </Paper>

WifValidatorPaper = (props) ->
  { wif, valid, details, onChange } = props
  <Paper>
    <Typography variant="h4">WIF Validator</Typography>
    <div style={{margin: "1%"}}>
      <ModifiableText
        value={wif}
        label="Private Key (WIF)"
        onChange={onChange}
      />
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

export default PrivateKeyPage
