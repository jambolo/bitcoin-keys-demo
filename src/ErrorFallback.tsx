import { Button } from "./components/ui/button";

import { AlertTriangleIcon, RefreshCwIcon } from "lucide-react";

interface ErrorFallbackProps {
  error: Error
  resetErrorBoundary: () => void
}

export const ErrorFallback = ({ error, resetErrorBoundary }: ErrorFallbackProps) => {
  // When encountering an error in the development mode, rethrow it and don't display the boundary.
  // The parent UI will take care of showing a more helpful dialog.
  if (import.meta.env.DEV) throw error;

  return (
    <div className="min-h-screen bg-background flex items-center justify-center p-4">
      <div className="w-full max-w-md">
        <div className="border border-destructive bg-destructive/10 rounded-lg p-4 mb-6">
          <div className="flex items-center gap-2 mb-2">
            <AlertTriangleIcon className="h-4 w-4 text-destructive" />
            <h2 className="font-semibold text-destructive">This spark has encountered a runtime error</h2>
          </div>
          <p className="text-sm text-muted-foreground">
            Something unexpected happened while running the application. The error details are shown below. Contact the spark author and let them know about this issue.
          </p>
        </div>
        
        <div className="bg-card border rounded-lg p-4 mb-6">
          <h3 className="font-semibold text-sm text-muted-foreground mb-2">Error Details:</h3>
          <pre className="text-xs text-destructive bg-muted/50 p-3 rounded border overflow-auto max-h-32">
            {error.message}
          </pre>
        </div>
        
        <Button 
          onClick={resetErrorBoundary} 
          className="w-full"
          variant="outline"
        >
          <RefreshCwIcon />
          Try Again
        </Button>
      </div>
    </div>
  );
}
