`
import { generatedWif, wifIsValidPrivateKey, wifIsValid, derivedPublicKey, decodedWif, hexIsValid, hexIsValidPublicKey } from './Common'
import { COMPRESSED_PUBLIC_KEY_SIZE, UNCOMPRESSED_PUBLIC_KEY_SIZE } from './Common'
import ModifiableText from './ModifiableText'

import Button from '@material-ui/core/Button'
import Paper from '@material-ui/core/Paper'
import React, { Component } from 'react'
import Typography from '@material-ui/core/Typography'
`

class PublicKeyPage extends Component
  constructor: (props) ->
    super props
    privateKeyWif = generatedWif()
    [ valid, compressed, prefix, privateKeyHex, check ] = decodedWif(privateKeyWif)
    publicKey = derivedPublicKey(privateKeyHex, compressed)
    @state = {
      privateKeyWif
      privateKeyHex
      compressed
      publicKey
      validator: {
        valid
        details: "Valid"
      }
    }
    return

  handleDerivationPrivateKeyWifChange: (value) =>
    [ valid, compressed, prefix, privateKeyHex, check ] = decodedWif(value)
    if not valid
      @setState { privateKeyHex: null, compressed: null, publicKey: null }
      return

    publicKey = derivedPublicKey(privateKeyHex, compressed)
    @setState { privateKeyHex, compressed, publicKey }
    return

  handleValidatorChange: (value) =>
    if not hexIsValid(Buffer.from(value))
      @setState { validator: { valid: false, details: "Invalid characters" }}
      return

    if value[0] != '0' or (value[1] != '2' and value[1] != '3' and value[1] != '4')
      @setState { validator: { valid: false, details: "Invalid prefix" }}
      return

    if (value[1] == '2' or value[1] == '3')
      if value.length != COMPRESSED_PUBLIC_KEY_SIZE * 2
        if value.length < COMPRESSED_PUBLIC_KEY_SIZE * 2
          @setState { validator: { valid: false, details: "Missing characters" }}
        else
          @setState { validator: { valid: false, details: "Extra characters" }}
        return
    else
      if value.length != UNCOMPRESSED_PUBLIC_KEY_SIZE * 2
        if value.length < UNCOMPRESSED_PUBLIC_KEY_SIZE * 2
          @setState { validator: { valid: false, details: "Missing characters" }}
        else
          @setState { validator: { valid: false, details: "Extra characters" }}
        return
    @setState { validator: { valid: true, details: "Valid" }}
    return


  render: () ->
    <div>
      <DerivationPaper
        privateKeyWif={@state.privateKeyWif}
        privateKeyHex={@state.privateKeyHex}
        compressed={@state.compressed}
        publicKey={@state.publicKey}
        privateKeyValidator={wifIsValid}
        onChange={@handleDerivationPrivateKeyWifChange}
      />
      <ValidationPaper
        publicKey={@state.publicKey}
        valid={@state.validator.valid}
        details={@state.validator.details}
        onChange={@handleValidatorChange}
      />
    </div>

DerivationPaper = (props) ->
  { privateKeyWif, privateKeyHex, compressed, publicKey, privateKeyValidator, onChange } = props
  <Paper>
    <Typography variant="h4">Derivation</Typography>
    <div style={{margin: "1%"}}>
      <Button variant="contained" color="primary" onClick={() => onChange(generatedWif())}>Random</Button>
      <ModifiableText
        value={privateKeyWif}
        validator={privateKeyValidator}
        label="Private Key (WIF)"
        helperText="invalid private key"
        onChange={onChange}
      />
      Private Key (hex):&nbsp;&nbsp;<span class="code"><b>{privateKeyHex.toString("hex")}</b></span><br/>
      Compressed:&nbsp;&nbsp;<b>{compressed.toString()}</b><br/>
      Public Key:&nbsp;&nbsp;<span class="code"><b>{publicKey.toString('hex')}</b></span>
    </div>
  </Paper>

ValidationPaper = (props) ->
  { publicKey, valid, details, onChange } = props
  <Paper>
    <Typography variant="h4">Validation</Typography>
    <div style={{margin: "1%"}}>
      <ModifiableText
        value={publicKey.toString('hex')}
        label="Public Key (hex)"
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


export default PublicKeyPaper
