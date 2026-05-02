import { ComponentProps } from 'react'
import {
  Box,
  Card as MuiCard,
  CardActions,
  CardContent as MuiCardContent,
  Typography,
} from '@mui/material'

function Card({ children, ...props }: ComponentProps<typeof MuiCard>) {
  return (
    <MuiCard {...props} sx={{ borderRadius: 2, ...(props.sx as object) }}>
      {children}
    </MuiCard>
  )
}

function CardHeader({ children, ...props }: ComponentProps<typeof Box>) {
  return (
    <Box {...props} sx={{ px: 3, pt: 3, pb: 1.5, ...(props.sx as object) }}>
      {children}
    </Box>
  )
}

function CardTitle({ children, ...props }: ComponentProps<typeof Typography>) {
  return (
    <Typography {...props} variant="h6" component="h3" sx={{ fontWeight: 600, ...(props.sx as object) }}>
      {children}
    </Typography>
  )
}

function CardDescription({ children, ...props }: ComponentProps<typeof Typography>) {
  return (
    <Typography {...props} variant="body2" color="text.secondary" sx={{ mt: 0.5, ...(props.sx as object) }}>
      {children}
    </Typography>
  )
}

function CardAction({ children, ...props }: ComponentProps<typeof Box>) {
  return (
    <Box {...props} sx={{ display: 'flex', justifyContent: 'flex-end', ...(props.sx as object) }}>
      {children}
    </Box>
  )
}

function CardContent({ children, ...props }: ComponentProps<typeof MuiCardContent>) {
  return <MuiCardContent {...props}>{children}</MuiCardContent>
}

function CardFooter({ children, ...props }: ComponentProps<typeof CardActions>) {
  return <CardActions {...props}>{children}</CardActions>
}

export {
  Card,
  CardHeader,
  CardFooter,
  CardTitle,
  CardAction,
  CardDescription,
  CardContent,
}
