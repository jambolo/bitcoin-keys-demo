`
import './App.css'
import AddressPaper from './AddressPaper'
import PrivateKeyPaper from './PrivateKeyPaper'
// import PublicKeyPaper from './PublicKeyPaper'
import TopBar from './TopBar'

import React, { Component } from 'react'
`

class App extends Component
  constructor: (props) ->
    super props
    @papers =
      "Private Key" : <PrivateKeyPaper app={this} />
#      "Public Key" :  <PublicKeyPaper app={this} />
      "Address" :     <AddressPaper app={this} />
    @state =
      demo:  "Private Key"
    return

  selectDemo: (label) =>
    @setState { demo: label }
    return

  render: ->
    <div className="App">
      <TopBar onChange={@selectDemo} tabs={Object.keys(@papers)} app={this} />
      { @papers[@state.demo] }
    </div>

export default App
