`
import Button from '@material-ui/core/Button';
import IconButton from '@material-ui/core/IconButton';
import React, { Component } from 'react';
import RefreshIcon from '@material-ui/icons/Refresh';
import TextField from '@material-ui/core/TextField';
import { makeStyles } from '@material-ui/core/styles';
`

class ModifiableText extends Component
  constructor: (props) ->
    super props
    @state =
      value: props.value
    return

  handleChange: (event) =>
    @setState { value: event.target.value }
    return

  handleKeyDown: (event) =>
    if event.keyCode == 13
      @props.onChange @state.value
    return

  handleClick: =>
    @props.onChange @state.value
    return

  render: ->
    valid = not @props.validator? or @props.validator(@state.value)
    <div>
      <ValidatedTextField
        value={@state.value}
        valid={valid}
        helperText={@props.helperText}
        onChange={@handleChange}
        onKeydown={@handleKeyDown} />
      {
        if valid
          <IconButton color="primary" aria-label="update" onClick={@handleClick} ><RefreshIcon /></IconButton>
        else
          <IconButton disabled aria-label="update" ><RefreshIcon /></IconButton>
      }
    </div>

ValidatedTextField = (props) ->
  { value, valid, helperText, onChange, onKeyDown } = props
  if valid
    <TextField 
      variant="outlined"
      autoFocus 
      margin="normal" 
      value={value} 
      onChange={onChange}
      onKeyDown={onKeyDown}
    />
  else
    <TextField 
      error
      variant="outlined"
      autoFocus 
      margin="normal" 
      value={value} 
      onChange={onChange}
      helperText={helperText}
    />

export default ModifiableText
