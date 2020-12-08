`
import { generatedWif, wifIsValidPrivateKey, wifIsValid, derivedPublicKey, decodedWif } from './Common'
import ModifiableText from './ModifiableText'

import Button from '@material-ui/core/Button'
import Paper from '@material-ui/core/Paper'
import React, { Component } from 'react'
import Typography from '@material-ui/core/Typography'
`

class PublicKeyPaper extends Component
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

  handlePrivateKeyWifChange: (value) =>
    [ valid, compressed, prefix, privateKeyHex, check ] = decodedWif(value)
    if not valid
      @setState { privateKeyHex: null, compressed: null, publicKey: null }
      return

    publicKey = derivedPublicKey(privateKeyHex, compressed)
    @setState { privateKeyHex, compressed, publicKey }
    return


  render: () ->
    <div>
      <DerivationPaper
        privateKeyWif={@state.privateKeyWif}
        privateKeyHex={@state.privateKeyHex}
        compressed={@state.compressed}
        publicKey={@state.publicKey}
        privateKeyValidator={wifIsValid}
        onChange={@handlePrivateKeyWifChange}
      />
      <AddressGenerationPaper />
      <ValidationPaper />
    </div>

DerivationPaper = (props) ->
  { privateKeyWif, privateKeyHex, compressed, publicKey, privateKeyValidator, onChange } = props
  <Paper variant="outlined">
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
      Compressed:&nbsp;&nbsp;{compressed.toString()}<br/>
      Public Key:&nbsp;&nbsp;<span class="code"><b>{publicKey.toString('hex')}</b></span>
    </div>
  </Paper>

AddressGenerationPaper = (props) ->
  <Paper variant="outlined">
    <Typography variant="h4">Address Generation</Typography>
  </Paper>

ValidationPaper = (props) ->
  <Paper variant="outlined">
    <Typography variant="h4">Validation</Typography>
  </Paper>


export default PublicKeyPaper
