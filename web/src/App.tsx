import { Loader2, Router, WifiOff } from 'lucide-react'
import { useCallback, useEffect, useState } from 'react'
import type { ReactNode } from 'react'
import { BrowserRouter, Link, Navigate, Route, Routes } from 'react-router-dom'
import { Toaster, toast } from 'sonner'
import { getSession, logout } from '@/api/client'
import { AppShell } from '@/components/app-shell'
import { useTheme } from '@/components/theme-provider'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { TooltipProvider } from '@/components/ui/tooltip'
import { ConnectionsPage } from '@/pages/connections'
import { LoginPage } from '@/pages/login'
import { NatPage } from '@/pages/nat'
import { OverviewPage } from '@/pages/overview'
import { SystemPage } from '@/pages/system'

type AuthState = {
  ready: boolean
  authenticated: boolean
  csrf: string | null
  error: string | null
}

export default function App() {
  const { resolvedTheme } = useTheme()
  const [auth, setAuth] = useState<AuthState>({
    ready: false,
    authenticated: false,
    csrf: null,
    error: null,
  })

  const loadSession = useCallback(async () => {
    setAuth((current) => ({ ...current, ready: false, error: null }))
    try {
      const session = await getSession()
      setAuth({
        ready: true,
        authenticated: session.authenticated,
        csrf: session.csrf ?? null,
        error: null,
      })
    } catch (error) {
      setAuth({
        ready: true,
        authenticated: false,
        csrf: null,
        error:
          error instanceof Error
            ? error.message
            : 'Could not reach vrouterweb. Check that the service is running.',
      })
    }
  }, [])

  useEffect(() => {
    void loadSession()
  }, [loadSession])

  useEffect(() => {
    function onUnauthorized() {
      setAuth({
        ready: true,
        authenticated: false,
        csrf: null,
        error: null,
      })
      toast.info('Session expired. Sign in again.')
    }
    window.addEventListener('vrouter:unauthorized', onUnauthorized)
    return () => window.removeEventListener('vrouter:unauthorized', onUnauthorized)
  }, [])

  async function signOut() {
    if (auth.csrf) {
      try {
        await logout(auth.csrf)
      } catch {
        // The local session is discarded even if the server already expired it.
      }
    }
    setAuth({ ready: true, authenticated: false, csrf: null, error: null })
    toast.success('Signed out')
  }

  let content: ReactNode
  if (!auth.ready) {
    content = <LoadingScreen />
  } else if (auth.error) {
    content = <ConnectionError message={auth.error} onRetry={() => void loadSession()} />
  } else if (!auth.authenticated) {
    content = (
      <LoginPage
        onSuccess={(csrf) =>
          setAuth({ ready: true, authenticated: true, csrf, error: null })
        }
      />
    )
  } else {
    content = (
      <BrowserRouter>
        <Routes>
          <Route element={<AppShell onSignOut={signOut} />}>
            <Route index element={<Navigate to="/overview" replace />} />
            <Route path="overview" element={<OverviewPage />} />
            <Route path="nat" element={<NatPage />} />
            <Route path="connections" element={<ConnectionsPage />} />
            <Route path="system" element={<SystemPage />} />
            <Route path="*" element={<NotFoundPage />} />
          </Route>
        </Routes>
      </BrowserRouter>
    )
  }

  return (
    <TooltipProvider delayDuration={200}>
      {content}
      <Toaster position="bottom-right" richColors closeButton theme={resolvedTheme} />
    </TooltipProvider>
  )
}

function LoadingScreen() {
  return (
    <div className="flex min-h-screen flex-col items-center justify-center gap-4 bg-background">
      <div className="flex size-12 items-center justify-center rounded-2xl bg-emerald-500 text-emerald-950 shadow-lg shadow-emerald-950/20">
        <Router className="size-6" />
      </div>
      <div className="flex items-center gap-2 text-sm text-muted-foreground">
        <Loader2 className="size-4 animate-spin" />
        Connecting to vrouterweb…
      </div>
    </div>
  )
}

function ConnectionError({ message, onRetry }: { message: string; onRetry: () => void }) {
  return (
    <div className="flex min-h-screen items-center justify-center bg-background px-4">
      <Card className="w-full max-w-md">
        <CardHeader>
          <div className="mb-2 flex size-10 items-center justify-center rounded-xl bg-rose-500/10 text-rose-600 dark:text-rose-300">
            <WifiOff className="size-5" />
          </div>
          <CardTitle>Cannot reach vrouterweb</CardTitle>
          <CardDescription>{message}</CardDescription>
        </CardHeader>
        <CardContent>
          <Button onClick={onRetry}>Try again</Button>
        </CardContent>
      </Card>
    </div>
  )
}

function NotFoundPage() {
  return (
    <div className="flex min-h-[60vh] flex-col items-center justify-center gap-3 text-center">
      <p className="text-sm font-medium text-muted-foreground">404</p>
      <h1 className="text-2xl font-semibold tracking-tight">Page not found</h1>
      <p className="max-w-sm text-sm text-muted-foreground">
        That page does not exist in the admin preview.
      </p>
      <Button asChild variant="outline">
        <Link to="/overview">Back to overview</Link>
      </Button>
    </div>
  )
}
