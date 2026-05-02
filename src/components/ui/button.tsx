import { Button as MuiButton, IconButton, type ButtonProps as MuiButtonProps } from '@mui/material'

type ButtonVariant = 'default' | 'destructive' | 'outline' | 'secondary' | 'ghost' | 'link'
type ButtonSize = 'default' | 'sm' | 'lg' | 'icon'

type Props = Omit<MuiButtonProps, 'variant' | 'size'> & {
  asChild?: boolean
  variant?: ButtonVariant
  size?: ButtonSize
}

const variantMap: Record<ButtonVariant, MuiButtonProps['variant']> = {
  default: 'contained',
  destructive: 'contained',
  outline: 'outlined',
  secondary: 'contained',
  ghost: 'text',
  link: 'text',
}

const sizeMap: Record<Exclude<ButtonSize, 'icon'>, MuiButtonProps['size']> = {
  default: 'medium',
  sm: 'small',
  lg: 'large',
}

function Button({ variant = 'default', size = 'default', asChild, sx, children, ...props }: Props) {
  if (size === 'icon') {
    return (
      <IconButton
        {...props}
        sx={{
          border: variant === 'outline' ? 1 : 0,
          borderColor: 'divider',
          ...(sx as object),
        }}
      >
        {children}
      </IconButton>
    )
  }

  return (
    <MuiButton
      {...props}
      variant={variantMap[variant]}
      size={sizeMap[size]}
      color={variant === 'destructive' ? 'error' : variant === 'secondary' ? 'secondary' : 'primary'}
      sx={{ textTransform: 'none', ...(sx as object) }}
    >
      {children}
    </MuiButton>
  )
}

export { Button }
