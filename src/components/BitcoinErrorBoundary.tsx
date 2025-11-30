import { Component, ReactNode } from 'react'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Warning } from '@phosphor-icons/react'

interface Props {
  children: ReactNode
  fallbackTitle?: string
}

interface State {
  hasError: boolean
  error?: Error
}

export class BitcoinErrorBoundary extends Component<Props, State> {
  constructor(props: Props) {
    super(props)
    this.state = { hasError: false }
  }

  static getDerivedStateFromError(error: Error): State {
    return { hasError: true, error }
  }

  componentDidCatch(error: Error, errorInfo: any) {
    console.error('Bitcoin component error:', error, errorInfo)
  }

  render() {
    if (this.state.hasError) {
      return (
        <Card className="border-destructive/50">
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-destructive">
              <Warning size={20} />
              {this.props.fallbackTitle || 'Component Error'}
            </CardTitle>
            <CardDescription>
              This component encountered an error and cannot be displayed.
              {this.state.error?.message && (
                <div className="mt-2 font-mono text-xs bg-muted p-2 rounded">
                  {this.state.error.message}
                </div>
              )}
            </CardDescription>
          </CardHeader>
          <CardContent>
            <p className="text-sm text-muted-foreground">
              This may be due to a browser compatibility issue. Please try refreshing the page.
            </p>
          </CardContent>
        </Card>
      )
    }

    return this.props.children
  }
}