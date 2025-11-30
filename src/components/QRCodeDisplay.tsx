import { useEffect, useRef, useState } from 'react'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import QRCode from 'qrcode'

interface QRCodeDisplayProps {
  value: string
  title: string
  size?: number
}

export function QRCodeDisplay({ value, title, size = 120 }: QRCodeDisplayProps) {
  const canvasRef = useRef<HTMLCanvasElement>(null)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    if (value && canvasRef.current) {
      const canvas = canvasRef.current
      setError(null)
      
      QRCode.toCanvas(canvas, value, {
        width: size,
        margin: 1,
        color: {
          dark: '#000000',
          light: '#ffffff'
        },
        errorCorrectionLevel: 'M'
      }).catch((error) => {
        console.error('QR Code generation failed:', error)
        setError(`Failed to generate QR code: ${error.message}`)
      })
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
        {error ? (
          <div className="text-xs text-destructive p-2 border border-destructive rounded bg-destructive/5">
            {error}
          </div>
        ) : (
          <canvas 
            ref={canvasRef}
            className="border border-border rounded"
          />
        )}
      </CardContent>
    </Card>
  )
}