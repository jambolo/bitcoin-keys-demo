`
import './App.css'
import AddressPage from './AddressPage'
import PrivateKeyPage from './PrivateKeyPage'
import PublicKeyPage from './PublicKeyPage'
import TopBar from './TopBar'

import React, { Component } from 'react'
`

class App extends Component
  constructor: (props) ->
    super props
    @pages =
      "Private Key" : <PrivateKeyPage app={this} />
      "Public Key" :  <PublicKeyPage app={this} />
      "Address" :     <AddressPage app={this} />
    @state =
      demo:  "Private Key"
    return

  selectDemo: (label) =>
    @setState { demo: label }
    return

  render: ->
    <div className="App">
      <TopBar onChange={@selectDemo} tabs={Object.keys(@pages)} app={this} />
      { @pages[@state.demo] }
    </div>

export default App
