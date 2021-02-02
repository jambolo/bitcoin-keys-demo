`
import { base58Address, generatedWif, hexIsValidPrivateKey, hexIsValidPublicKey, encodedWif, decodedWif, publicKey, pubkeyHash, wifIsValid, decodedBase58Address } from './Common'
import { P2PKH_PREFIX, P2SH_PREFIX } from './Common'
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
    p2pkh = {}
    [ p2pkh.address, p2pkh.check ] = base58Address(pubKey, P2PKH_PREFIX)
    p2sh = {}
    [ p2sh.address, p2sh.check ] = base58Address(pubKey, P2SH_PREFIX)

    @state = {
      wif
      privateKey: privKey
      compressed
      publicKey: pubKey
      pubkeyHash: hash
      p2pkh
      p2sh
      validator: {
        address: p2pkh.address
        prefix: P2PKH_PREFIX
        pubKeyHash: hash
        check: p2pkh.check
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
        pubkeyHash: null
        p2pkh:
          check: null
          address: null
        p2sh:
          check: null
          address: null
        validator:
          address: null
          prefix: null
          pubKeyHash: null
          check: null
          valid: false
          details: null
      }
      return

    pubKey = publicKey(privKey, compressed)
    hash = pubkeyHash(pubKey)
    p2pkh = {}
    [ p2pkh.address, p2pkh.check ] = base58Address(pubKey, P2PKH_PREFIX)
    p2sh = {}
    [ p2sh.address, p2sh.check ] = base58Address(pubKey, P2SH_PREFIX)

    @setState {
      wif: valueBuf
      privateKey: privKey
      compressed
      publicKey: pubKey
      pubkeyHash: hash
      p2pkh
      p2sh
      validator:
        address: p2pkh.address
        prefix: P2PKH_PREFIX
        pubKeyHash: hash
        check: p2pkh.check
        valid: true
        details: "Valid"
    }
    return

  handlePrivateKeyChange: (value) =>
    valueBuf = Buffer.from(value)
    if not hexIsValidPrivateKey(valueBuf)
      @setState {
        wif: null
        privateKey: valueBuf
        compressed: null
        publicKey: null
        pubkeyHash: null
        p2pkh:
          check: null
          address: null
        p2sh:
          check: null
          address: null
        validator:
          address: null
          prefix: null
          pubKeyHash: null
          check: null
          valid: false
          details: null
      }
      return

    privKey = Buffer.from(value, 'hex')
    [ compressedWif ] = encodedWif(privKey, true, 0x80)
    pubKey = publicKey(privKey, true)
    hash = pubkeyHash(pubKey)
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
      pubkeyHash: hash
      p2pkh
      p2sh
      validator:
        address: p2pkh.address
        prefix: P2PKH_PREFIX
        pubKeyHash: hash
        check: p2pkh.check
        valid: true
        details: "Valid"
    }
    return

  handlePublicKeyChange: (value) =>
    return

  handleValidatorChange: (value) =>
    valueBuf = Buffer.from(value)
    [valid, hash, prefix, check] = decodedBase58Address(valueBuf)
    if not valid
      @setState {
        validator:
          address: valueBuf
          prefix: null
          pubKeyHash: null
          check: null
          valid: false
          details: "Invalid"
      }
    else
      @setState {
        validator: {
          address: valueBuf
          prefix
          pubKeyHash: hash
          check
          valid: true
          details: "Valid"
        }
      }
    return

  render: ->
    <div>
      <DerivationPaper
        wif={@state.wif}
        privKey={@state.privateKey}
        compressed={@state.compressed}
        pubKey={@state.publicKey}
        hash={@state.pubkeyHash}
        p2pkh={@state.p2pkh}
        p2sh={@state.p2sh}
        onWifChange={@handleWifChange}
        onPrivateKeyChange={@handlePrivateKeyChange}
        onPublicKeyChange={@handlePublicKeyChange}
      />
      <ValidationPaper
        address={@state.validator.address}
        prefix={@state.validator.prefix}
        pubKeyHash={@state.validator.pubKeyHash}
        check={@state.validator.check}
        valid={@state.validator.valid}
        details={@state.validator.details}
        onChange={@handleValidatorChange}
      />
    </div>

DerivationPaper = (props) ->
  { wif, privKey, compressed, pubKey, hash, p2pkh, p2sh, onWifChange, onPrivateKeyChange, onPublicKeyChange } = props
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
      PubkeyHash:&nbsp;&nbsp;<b><span class="code">{hash.toString('hex')}</span></b><br/>
      <br/>
      <Typography variant="h5">P2PKH</Typography>
      <div style={{margin: "1%"}}>
        <Typography variant="h6">Checksum</Typography>
        <div style={{margin: "1%"}}>
          <span class="code">00&nbsp;{hash.toString('hex')}</span>
          &nbsp;&nbsp;⟹&nbsp;&nbsp;
          SHA-256(SHA-256())
          &nbsp;&nbsp;⟹&nbsp;&nbsp;
          <b><span class="code">{p2pkh.check.toString('hex')}</span></b>
        </div>
        <Typography variant="h6">Address</Typography>
        <div style={{margin: "1%"}}>
          <span class="code">00&nbsp;{hash.toString('hex')}&nbsp;{p2pkh.check.toString('hex')}</span>
          &nbsp;&nbsp;⟹&nbsp;&nbsp;
          Base58()
          &nbsp;&nbsp;⟹&nbsp;&nbsp;
          <b><span class="code">{p2pkh.address.toString()}</span></b>
        </div>
      </div>
      <Typography variant="h5">P2SH</Typography>
      <div style={{margin: "1%"}}>
        <Typography variant="h6">Checksum</Typography>
        <div style={{margin: "1%"}}>
          <span class="code">05&nbsp;{hash.toString('hex')}</span>
          &nbsp;&nbsp;⟹&nbsp;&nbsp;
          SHA-256(SHA-256())
          &nbsp;&nbsp;⟹&nbsp;&nbsp;
          <b><span class="code">{p2sh.check.toString('hex')}</span></b>
        </div>
        <Typography variant="h6">Address</Typography>
        <div style={{margin: "1%"}}>
          <span class="code">05&nbsp;{hash.toString('hex')}&nbsp;{p2sh.check.toString('hex')}</span>
          &nbsp;&nbsp;⟹&nbsp;&nbsp;
          Base58()
          &nbsp;&nbsp;⟹&nbsp;&nbsp;
          <b><span class="code">{p2sh.address.toString()}</span></b>
        </div>
      </div>
      <Typography variant="h5">Bech32</Typography>
      <div style={{margin: "1%"}}>
      </div>
    </div>
  </Paper>

ValidationPaper = (props) ->
  { address, prefix, pubKeyHash, check, valid, details, onChange } = props
  <Paper>
    <Typography variant="h4">Validation</Typography>
    <div style={{margin: "1%"}}>
      <ModifiableText
        value={address.toString()}
        label="Address"
        onChange={onChange}
      />
      Prefix:&nbsp;&nbsp;<b><span class="code">{prefix.toString(16)}</span></b><br/>
      PubKeyHash:&nbsp;&nbsp;<b><span class="code">{pubKeyHash.toString('hex')}</span></b><br/>
      Check:&nbsp;&nbsp;<b><span class="code">{check.toString('hex')}</span></b>
      <br/>
      <br/>
      {
        if valid
          <b><span style={{color: "green"}}>{details}</span></b>
        else
          <b><span style={{color: "red"}}>{details}</span></b>
      }
    </div>
  </Paper>

export default AddressPage
