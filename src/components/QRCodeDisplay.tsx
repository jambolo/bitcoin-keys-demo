import { useEffect, useRef } from 'react'
import QRCode from 'qrcode'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'

interface QRCodeDisplayProps {
  value: string
  title: string
  size?: number
}

export function QRCodeDisplay({ value, title, size = 120 }: QRCodeDisplayProps) {
  const canvasRef = useRef<HTMLCanvasElement>(null)

  useEffect(() => {
    if (value && canvasRef.current) {
      QRCode.toCanvas(canvasRef.current, value, {
        width: size,
        margin: 2,
        color: {
          dark: '#000000',
          light: '#ffffff'
        }
      }).catch(console.error)
    }
  }, [value, size])

  if (!value) {
    return null
  }

  return (
    <Card className="w-fit">
      <CardHeader className="pb-2">
        <CardTitle className="text-sm text-center">{title}</CardTitle>
      </CardHeader>
      <CardContent className="pt-0 flex justify-center">
        <canvas 
          ref={canvasRef}
          className="border border-border rounded"
        />
      </CardContent>
    </Card>
  )
}