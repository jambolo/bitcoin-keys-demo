import { TextField, type TextFieldProps } from '@mui/material'

function Textarea({ rows, ...props }: TextFieldProps) {
  return (
    <TextField {...props} multiline rows={rows ?? 3} variant="outlined" size="small" fullWidth />
  )
}

export { Textarea }
