import { useEffect, useRef } from 'react'
import QRCodeLib from 'qrcode'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'

interface QRCodeProps {
  value: string
  title?: string
  size?: number
  className?: string
}

export function QRCode({ value, title, size = 128, className = '' }: QRCodeProps) {
  const canvasRef = useRef<HTMLCanvasElement>(null)

  useEffect(() => {
    if (!value || !canvasRef.current) return

    QRCodeLib.toCanvas(canvasRef.current, value, {
      width: size,
      margin: 2,
      color: {
        dark: '#1f2937', // Using a slightly softer dark for better visibility
        light: '#ffffff'
      }
    }).catch(err => {
      console.error('QR Code generation failed:', err)
    })
  }, [value, size])

  if (!value) return null

  if (title) {
    return (
      <Card className={`${className} border border-border`}>
        <CardHeader className="pb-2">
          <CardTitle className="text-xs font-medium text-center">{title}</CardTitle>
        </CardHeader>
        <CardContent className="flex justify-center pb-3">
          <canvas ref={canvasRef} className="border border-border/20 rounded" />
        </CardContent>
      </Card>
    )
  }

  return (
    <div className={`flex justify-center ${className}`}>
      <canvas ref={canvasRef} className="border border-border/20 rounded" />
    </div>
  )
}