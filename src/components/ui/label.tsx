import { ComponentProps } from 'react'
import { Typography } from '@mui/material'

function Label({ children, ...props }: ComponentProps<'label'>) {
  return (
    <Typography component="label" variant="body2" sx={{ fontWeight: 500 }} {...props}>
      {children}
    </Typography>
  )
}

export { Label }
