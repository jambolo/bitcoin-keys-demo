`
// import { generatePrivateKey, encodeWif, decodeWif, hexPrivateKeyValidator, wifValidator, computeChecksum } from './Common'
// import { PRIVATE_KEY_SIZE, MIN_PRIVATE_KEY, MAX_PRIVATE_KEY } from './Common'

// import Paper from '@material-ui/core/Paper'
import React, { Component } from 'react'
`

#.my-card-content {
#  padding: 16px;
#}
#.my-card {
#  height: 100px;
#  width: 300px;
#}

class AddressPaper extends Component
  constructor: (props) ->
    super props

    @privateKey = ""
    @compressed =
      publicKey: ""
      p2pkhAddress: ""
      p2shAddress: ""
      bech32Address: ""
    @uncompressed =
      publicKey: ""
      p2pkhAddress: ""
      p2shAddress: ""
      bech32Address: ""
    return

  render: ->
    <div>
      Private Key : {@privateKey}<br/>
      Compressed Public Key : {@compressed.publicKey}<br/>
      Compressed P2PKH Address : {@compressed.p2pkhAddress}<br/>
      Compressed P2SH Address : {@compressed.p2shAddress}<br/>
      Compressed Bech32 Address : {@compressed.bech32Address}<br/>
      Uncompressed Public Key : {@uncompressed.publicKey}<br/>
      Uncompressed P2PKH Address : {@uncompressed.p2pkhAddress}<br/>
      Uncompressed P2SH Address : {@uncompressed.p2shAddress}<br/>
      Uncompressed Bech32 Address : {@uncompressed.bech32Address}<br/>
    </div>

export default AddressPaper