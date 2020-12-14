`
import { address, generatedWif, hexIsValidPrivateKey, hexIsValidPublicKey, decodedWif, publicKey, pubkeyHash, wifIsValid } from './Common'

import ModifiableText from './ModifiableText'

import Button from '@material-ui/core/Button'
import Paper from '@material-ui/core/Paper'
import React, { Component } from 'react'
import Typography from '@material-ui/core/Typography'
`

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
    hash = pubkeyHash(pubKey)
    prefix = 0
    [addr, check ] = address(pubKey, prefix)
    @state = {
      wif
      privateKey: privKey
      compressed
      publicKey: pubKey
      pubkeyHash: hash
      prefix
      address: addr
      check
      validator: {
        valid
        details: "Valid"
      }
    }

  handleWifChange: (value) ->
    return

  handlePrivateKeyChange: (value) ->
    return

  handlePublicKeyChange: (value) ->
    return

  handleValidatorChange: (value) ->
    return

  render: ->
    <div>
      <DerivationPaper
        wif={@state.wif}
        privKey={@state.privateKey}
        compressed={@state.compressed}
        pubKey={@state.publicKey}
        hash={@state.pubkeyHash}
        prefix={@state.prefix}
        addr={@state.address}
        onWifChange={@handleWifChange}
        onPrivateKeyChange={@handlePrivateKeyChange}
        onPublicKeyChange={@handlePublicKeyChange}
      />
      <ValidationPaper
        addr={@state.address}
        valid={@state.validator.valid}
        details={@state.validator.details}
        onChange={@handleValidatorChange}
      />
    </div>

DerivationPaper = (props) ->
  { wif, privKey, compressed, pubKey, hash, prefix, addr, onWifChange, onPrivateKeyChange, onPublicKeyChange } = props
  <Paper>
    <Typography variant="h4">Derivation</Typography>
    <div style={{margin: "1%"}}>
      <Button variant="contained" color="primary" onClick={() => onWifChange(generatedWif())}>Random</Button>
      <ModifiableText
        value={wif.toString()}
        validator={wifIsValid}
        label="Private Key (WIF)"
        helperText="invalid private key"
        onChange={onWifChange}
      />
      <ModifiableText
        value={privKey.toString('hex')}
        validator={hexIsValidPrivateKey}
        label="Private Key (hex)"
        helperText="invalid private key"
        onChange={onPrivateKeyChange}
      />
      Compressed  :&nbsp;&nbsp;<b><span class="code">{compressed.toString()}</span></b><br/>
      <ModifiableText
        value={pubKey.toString('hex')}
        validator={hexIsValidPublicKey}
        label="Public Key (hex)"
        helperText="invalid private key"
        onChange={onPublicKeyChange}
      />
      PubkeyHash  :&nbsp;&nbsp;<b><span class="code">{hash.toString('hex')}</span></b><br/>
      Prefix      :&nbsp;&nbsp;<b><span class="code">{prefix}</span></b><br/>
      Address     :&nbsp;&nbsp;<b><span class="code">{addr.toString()}</span></b><br/>
    </div>
  </Paper>

ValidationPaper = (props) ->
  { addr, valid, details, onChange } = props
  <Paper>
    <Typography variant="h4">Validation</Typography>
    <div style={{margin: "1%"}}>
      <ModifiableText
        value={addr.toString('hex')}
        label="Address"
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


export default AddressPage
