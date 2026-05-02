import { ComponentProps } from 'react'
import { Chip } from '@mui/material'

type BadgeVariant = 'default' | 'secondary' | 'destructive' | 'outline'

function Badge({ children, variant = 'default', ...props }: ComponentProps<'span'> & { variant?: BadgeVariant }) {
  const color = variant === 'destructive' ? 'error' : variant === 'secondary' ? 'secondary' : 'primary'
  return (
    <Chip
      {...props}
      label={children}
      size="small"
      color={color}
      variant={variant === 'outline' ? 'outlined' : 'filled'}
      sx={{ height: 22, borderRadius: 1.5 }}
    />
  )
}

export { Badge }
