import { Activity, ArrowRight, Eye, EyeOff, LockKeyhole, Router, ShieldCheck } from 'lucide-react'
import { useState } from 'react'
import type { FormEvent } from 'react'
import { ApiError, getSession, login } from '@/api/client'
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'

export function LoginPage({ onSuccess }: { onSuccess: (csrf: string) => void }) {
  const [password, setPassword] = useState('')
  const [showPassword, setShowPassword] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [pending, setPending] = useState(false)

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    if (!password) {
      setError('Enter the admin password.')
      return
    }
    setPending(true)
    setError(null)
    try {
      const response = await login(password)
      const csrf = response.csrf ?? (await getSession()).csrf ?? ''
      onSuccess(csrf)
    } catch (err) {
      setError(
        err instanceof ApiError
          ? err.message
          : 'Could not reach vrouterweb. Check that the service is running.',
      )
    } finally {
      setPending(false)
    }
  }

  return (
    <div className="grid min-h-screen bg-background lg:grid-cols-[1.1fr_1fr]">
      <section className="relative hidden overflow-hidden bg-[#07130f] p-10 text-white lg:flex lg:flex-col lg:justify-between">
        <div className="absolute inset-0 bg-[radial-gradient(circle_at_20%_15%,rgba(16,185,129,0.22),transparent_32%),radial-gradient(circle_at_80%_80%,rgba(45,212,191,0.12),transparent_38%)]" />
        <div className="relative flex items-center gap-3">
          <div className="flex size-10 items-center justify-center rounded-xl bg-emerald-400 text-emerald-950">
            <Router className="size-5" />
          </div>
          <div>
            <div className="font-semibold tracking-tight">vRouter</div>
            <div className="text-xs text-white/50">Admin preview</div>
          </div>
        </div>

        <div className="relative max-w-lg space-y-6">
          <div className="inline-flex items-center gap-2 rounded-full border border-emerald-400/20 bg-emerald-400/10 px-3 py-1 text-xs font-medium text-emerald-300">
            <Activity className="size-3.5" />
            Local control plane
          </div>
          <h1 className="text-4xl font-semibold leading-tight tracking-tight text-balance xl:text-5xl">
            Your network, without the noise.
          </h1>
          <p className="text-base leading-relaxed text-white/60">
            Inspect forwarding, NAT and live connection state from a focused,
            read-only console. Nothing here changes the router.
          </p>
          <div className="grid gap-3 text-sm text-white/70">
            <div className="flex items-center gap-3">
              <ShieldCheck className="size-4 text-emerald-400" />
              Session-protected, loopback-only access
            </div>
            <div className="flex items-center gap-3">
              <LockKeyhole className="size-4 text-emerald-400" />
              State is read through the local Unix socket
            </div>
          </div>
        </div>

        <p className="relative text-xs text-white/35">
          vRouter 0.2 preview · read-only by design
        </p>
      </section>

      <section className="flex items-center justify-center px-4 py-10 sm:px-8">
        <div className="w-full max-w-md space-y-6">
          <div className="flex items-center gap-3 lg:hidden">
            <div className="flex size-10 items-center justify-center rounded-xl bg-emerald-500 text-emerald-950">
              <Router className="size-5" />
            </div>
            <div>
              <div className="font-semibold tracking-tight">vRouter</div>
              <div className="text-xs text-muted-foreground">Admin preview</div>
            </div>
          </div>

          <Card className="border-border/70 shadow-xl shadow-black/5">
            <CardHeader className="space-y-1.5">
              <CardTitle className="text-2xl">Sign in</CardTitle>
              <CardDescription>
                Use the password configured for the local web admin.
              </CardDescription>
            </CardHeader>
            <CardContent>
              <form className="space-y-5" onSubmit={(event) => void submit(event)}>
                <div className="space-y-2">
                  <Label htmlFor="password">Admin password</Label>
                  <div className="relative">
                    <Input
                      id="password"
                      name="password"
                      type={showPassword ? 'text' : 'password'}
                      value={password}
                      onChange={(event) => setPassword(event.target.value)}
                      autoComplete="current-password"
                      autoFocus
                      className="pr-10"
                      placeholder="Enter password"
                      disabled={pending}
                    />
                    <Button
                      type="button"
                      variant="ghost"
                      size="icon"
                      className="absolute right-1 top-1/2 size-8 -translate-y-1/2 text-muted-foreground"
                      aria-label={showPassword ? 'Hide password' : 'Show password'}
                      onClick={() => setShowPassword((visible) => !visible)}
                      disabled={pending}
                    >
                      {showPassword ? <EyeOff className="size-4" /> : <Eye className="size-4" />}
                    </Button>
                  </div>
                </div>

                {error ? (
                  <Alert variant="destructive">
                    <AlertTitle>Sign-in failed</AlertTitle>
                    <AlertDescription>{error}</AlertDescription>
                  </Alert>
                ) : null}

                <Button type="submit" className="w-full" disabled={pending}>
                  {pending ? 'Signing in…' : 'Sign in'}
                  {!pending ? <ArrowRight className="size-4" /> : null}
                </Button>
              </form>
            </CardContent>
          </Card>

          <p className="text-center text-xs leading-relaxed text-muted-foreground">
            This console is read-only. Use the vRouter CLI for configuration changes.
          </p>
        </div>
      </section>
    </div>
  )
}
