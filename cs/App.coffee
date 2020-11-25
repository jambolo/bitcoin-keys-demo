`
import './App.css';
import AddressCard from './AddressCard'
import PrivateKeyCard from './PrivateKeyCard'

import React, { Component } from 'react';
`

class App extends Component
  constructor: (props) ->
    super props
    return

  render: ->
    <div className="App">
      <PrivateKeyCard app={this} />
    </div>

export default App
