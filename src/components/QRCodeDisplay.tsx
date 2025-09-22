import { useEffect, useRef } from 'react'
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
      const canvas = canvasRef.current
      const ctx = canvas.getContext('2d')
      if (!ctx) return

      // Simple QR-like pattern generation for demonstration
      const cellSize = Math.floor(size / 25)
      canvas.width = cellSize * 25
      canvas.height = cellSize * 25
      
      ctx.fillStyle = '#ffffff'
      ctx.fillRect(0, 0, canvas.width, canvas.height)
      
      ctx.fillStyle = '#000000'
      
      // Generate a simple pattern based on the value hash
      let hash = 0
      for (let i = 0; i < value.length; i++) {
        hash = ((hash << 5) - hash + value.charCodeAt(i)) & 0xffffffff
      }
      
      // Create a pseudo-random pattern
      for (let x = 0; x < 25; x++) {
        for (let y = 0; y < 25; y++) {
          const seed = (hash + x * 25 + y) & 0xffffffff
          if ((seed % 3) === 0) {
            ctx.fillRect(x * cellSize, y * cellSize, cellSize, cellSize)
          }
        }
      }
      
      // Add corner markers
      const markerSize = cellSize * 3
      ctx.fillRect(0, 0, markerSize, markerSize)
      ctx.fillRect(canvas.width - markerSize, 0, markerSize, markerSize)
      ctx.fillRect(0, canvas.height - markerSize, markerSize, markerSize)
      
      ctx.fillStyle = '#ffffff'
      const innerSize = cellSize
      ctx.fillRect(cellSize, cellSize, innerSize, innerSize)
      ctx.fillRect(canvas.width - markerSize + cellSize, cellSize, innerSize, innerSize)
      ctx.fillRect(cellSize, canvas.height - markerSize + cellSize, innerSize, innerSize)
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