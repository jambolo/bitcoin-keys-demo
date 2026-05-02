import { forwardRef } from 'react'
import { TextField, type TextFieldProps } from '@mui/material'

const Input = forwardRef<HTMLInputElement, Omit<TextFieldProps, 'variant'>>(
  function Input({ size, ...props }, ref) {
    return (
      <TextField
        {...props}
        inputRef={ref}
        size={size ?? 'small'}
        variant="outlined"
        fullWidth={props.fullWidth ?? true}
      />
    )
  }
)

export { Input }
