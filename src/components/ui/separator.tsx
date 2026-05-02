import { Divider } from '@mui/material'

function Separator({
  orientation = "horizontal",
}: {
  orientation?: 'horizontal' | 'vertical'
  decorative?: boolean
}) {
  return (
    <Divider
      orientation={orientation}
      sx={{ my: orientation === 'horizontal' ? 1 : 0 }}
    />
  )
}

export { Separator }
