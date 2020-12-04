`
import { generatePrivateKey, encodeWif, decodeWif, hexPrivateKeyValidator, wifValidator, computeChecksum } from './Common'
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
    @state = {}
    @state.privateKey = generatePrivateKey()
    [ @state.compressedWif, @state.compressedChecksum ] = encodeWif(0x80, @state.privateKey, true)
    [ @state.uncompressedWif, @state.uncompressedChecksum ] = encodeWif(0x80, @state.privateKey, false)
    @state.prefix = 0x80
    @state.compressed = true
    @state.validator =
      wif: @state.compressedWif
      valid: true
      details: "Valid"
    return

  handlePrivateKeyHexChange: (value) =>
    privateKey = Buffer.from(value, 'hex')
    [ compressedWif, compressedChecksum ] = encodeWif(0x80, privateKey, true)
    [ uncompressedWif, uncompressedChecksum ] = encodeWif(0x80, privateKey, false)
    @setState { privateKey, compressedWif, compressedChecksum, uncompressedWif, uncompressedChecksum, prefix: 0x80, compressed: true }
    return

  handlePrivateKeyWifChange: (value) =>
    [ valid, compressed, prefix, privateKey ] = decodeWif(value)
    if valid
      [ compressedWif, compressedChecksum ] = encodeWif(0x80, privateKey, true)
      [ uncompressedWif, uncompressedChecksum ] = encodeWif(0x80, privateKey, false)
      @setState { privateKey, compressedWif, compressedChecksum, uncompressedWif, uncompressedChecksum, prefix, compressed }
    return      

  handleValidatorChange: (value) =>
    # Check characters before attempting to decode
    if value.match(/^[123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz]+$/) == null
      @setState { validator: { wif: value, valid: false, details: "Invalid characters" }}
      return

    work = Buffer.from(Base58.decode(value))
    console.log "handleValidatorChange: work.length=#{work.length}"
    # Check if uncompressed private key
    if work.length == DECODED_UNCOMPRESSED_PRIVATE_KEY_SIZE
      prefix = work[0]
      privateKey = work.slice(1, 1 + PRIVATE_KEY_SIZE)
      checksum = work.slice(1 + PRIVATE_KEY_SIZE)
      computed = computeChecksum(work.slice(0, 1 + PRIVATE_KEY_SIZE))
      if checksum.compare(computed) != 0
        @setState { validator: { wif: value, valid: false, details: "Checksum mismatch" }}
      else if prefix != 0x80
        @setState { validator: { wif: value, valid: false, details: "Invalid prefix" }}
      else if privateKey.compare(MIN_PRIVATE_KEY) < 0 or privateKey.compare(MAX_PRIVATE_KEY) > 0
        @setState { validator: { wif: value, valid: false, details: "Private key is outside of the valid range" }}
      else
        @setState { validator: { wif: value, valid: true, details: "Valid" }}
      return

    # Check if compressed private key
    if work.length == DECODED_COMPRESSED_PRIVATE_KEY_SIZE
      prefix = work[0]
      privateKey = work.slice(1, 1 + PRIVATE_KEY_SIZE)
      compressed = work[1 + PRIVATE_KEY_SIZE]
      checksum = work.slice(1 + PRIVATE_KEY_SIZE + 1)
      computed = computeChecksum(work.slice(0, 1 + PRIVATE_KEY_SIZE + 1))
      if checksum.compare(computed) != 0
        @setState { validator: { wif: value, valid: false, details: "Checksum mismatch" }}
      else if prefix != 0x80
        @setState { validator: { wif: value, valid: false, details: "Invalid prefix" }}
      else if privateKey.compare(MIN_PRIVATE_KEY) < 0 or privateKey.compare(MAX_PRIVATE_KEY) > 0
        @setState { validator: { wif: value, valid: false, details: "Private key is outside of the valid range" }}
      else if compressed != 1
        @setState { validator: { wif: value, valid: false, details: "Invalid compressed flag value" }}
      else
        @setState { validator: { wif: value, valid: true, details: "Valid" }}
      return

    # Too many or too few ...
    if work.length < DECODED_UNCOMPRESSED_PRIVATE_KEY_SIZE
      @setState { validator: { wif: value, valid: false, details: "Missing characters" }}
    else
      @setState { validator: { wif: value, valid: false, details: "Extra characters" }}
    return

  render: ->
    <div>
      <WifEncodingPaper
        privateKey={@state.privateKey}
        uncompressedChecksum={@state.uncompressedChecksum}
        uncompressedWif={@state.uncompressedWif}
        compressedChecksum={@state.compressedChecksum}
        compressedWif={@state.compressedWif}
        privateKeyValidator={hexPrivateKeyValidator}
        onChange={@handlePrivateKeyHexChange}
      />
      <WifDecodingPaper
        privateKeyWif={if @state.compressed then @state.compressedWif else @state.uncompressedWif}
        prefix={@state.prefix}
        privateKey={@state.privateKey}
        compressed={@state.compressed}
        checksum={if @state.compressed then @state.compressedChecksum else @state.uncompressedChecksum}
        wifValidator={wifValidator}
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

  <div>
    <Paper variant='outlined' square />
    <div style={{margin: "1%"}}>
      <Typography variant="h4">WIF Encoding</Typography>
      <div style={{margin: "1%"}}>
        <Typography variant="h5">Private Key (hex):</Typography>
        <div style={{margin: "1%"}}>
          <Button variant="contained" color="primary" onClick={() => onChange(generatePrivateKey().toString('hex'))}>Random</Button>
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
            <span class="code">80|{privateKey.toString('hex')}</span>
            &nbsp;⟹&nbsp;
            SHA-256(SHA-256())
            &nbsp;⟹&nbsp;
            <span class="code"><b>{uncompressedChecksum.toString('hex')}</b></span>
          </div>
          <Typography variant="h6">WIF:</Typography>
          <div style={{margin: "1%"}}>
            <span class="code">80|{privateKey.toString('hex')}|{uncompressedChecksum.toString('hex')}</span>
            &nbsp;⟹&nbsp;
            Base58()
            &nbsp;⟹&nbsp;
            <b>{uncompressedWif.toString()}</b>
          </div>
        </div>
        <Typography variant="h5">Compressed:</Typography>
        <div style={{margin: "1%"}}>
          <Typography variant="h6">Checksum:</Typography>
          <div style={{margin: "1%"}}>
            <span class="code">80|{privateKey.toString('hex')}|01</span>
            &nbsp;⟹&nbsp;
            SHA-256(SHA-256())
            &nbsp;⟹&nbsp;
            <span class="code"><b>{compressedChecksum.toString('hex')}</b></span>
          </div>
          <Typography variant="h6">WIF:</Typography>
          <div style={{margin: "1%"}}>
            <span class="code"> 80|{privateKey.toString('hex')}|01|{compressedChecksum.toString('hex')}</span>
            &nbsp;⟹&nbsp;
            Base58()
            &nbsp;⟹&nbsp;
            <b>{compressedWif.toString()}</b>
          </div>
        </div>
      </div>
    </div>
  </div>

WifDecodingPaper = (props) ->
  { privateKeyWif, prefix, privateKey, compressed, checksum, wifValidator, onChange } = props
  <div>
    <Paper variant='outlined' square />
    <div style={{margin: "1%"}}>
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
    </div>
  </div>

WifValidatorPaper = (props) ->
  { privateKeyWif, valid, details, onChange } = props
  <div>
    <Paper variant='outlined' square />
    <div style={{margin: "1%"}}>
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
    </div>
  </div>

export default PrivateKeyPaper
