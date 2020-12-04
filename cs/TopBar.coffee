`
import AppBar from '@material-ui/core/AppBar'
import Tab from '@material-ui/core/Tab'
import Tabs from '@material-ui/core/Tabs'
import React from 'react'
`

TopBar = (props) ->
  [value, setValue] = React.useState(0)

  handleChange = (event, newValue) =>
    setValue newValue
    props.onChange props.tabs[newValue]
    return

  <div>
    <AppBar position="static">
      <Tabs value={value} onChange={handleChange} aria-label="demo selection">
        { <Tab label={label} key={i} /> for label, i in props.tabs }
      </Tabs>
    </AppBar>
  </div>

export default TopBar
