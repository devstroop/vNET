import type { ReactNode } from 'react'
import {
  Clock3,
  FileText,
  FolderCog,
  Info,
  LockKeyhole,
  RefreshCw,
  Router,
  Server,
  ShieldCheck,
  Terminal,
} from 'lucide-react'
import { getStatus } from '@/api/client'
import { CopyButton } from '@/components/copy-button'
import { PageHeader } from '@/components/page-header'
import { ErrorState, LoadingCards } from '@/components/states'
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Separator } from '@/components/ui/separator'
import { useResource } from '@/hooks/use-resource'
import { formatDateTime, formatDuration, formatNumber } from '@/lib/format'

export function SystemPage() {
  const { data, error, loading, refresh } = useResource(getStatus, 0)
  const status = data?.status

  return (
    <div className="space-y-6">
      <PageHeader
        title="System"
        description="Runtime identity and paths reported by the vRouter daemon."
        actions={
          <Button variant="outline" size="sm" onClick={() => void refresh()}>
            <RefreshCw className={loading ? 'size-4 animate-spin' : 'size-4'} />
            Refresh
          </Button>
        }
      />

      {error && !status ? <ErrorState message={error} onRetry={() => void refresh()} /> : null}
      {loading && !status ? <LoadingCards count={4} /> : null}

      {status ? (
        <>
          <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
            <InfoCard icon={<Router className="size-4" />} label="Instance" value={status.instance || '—'} />
            <InfoCard icon={<Server className="size-4" />} label="Version" value={status.version || '—'} />
            <InfoCard icon={<Terminal className="size-4" />} label="PID" value={formatNumber(status.pid)} />
            <InfoCard icon={<FolderCog className="size-4" />} label="Ports" value={formatNumber(status.ports)} />
          </div>

          <div className="grid gap-4 lg:grid-cols-2">
            <Card>
              <CardHeader>
                <CardTitle>Runtime</CardTitle>
                <CardDescription>Process and lifecycle metadata.</CardDescription>
              </CardHeader>
              <CardContent className="space-y-3 text-sm">
                <MetaRow label="Started" value={formatDateTime(status.started_ms)} />
                <MetaRow label="Updated" value={formatDateTime(status.updated_ms)} />
                <MetaRow label="Uptime" value={formatDuration(status.uptime_ms)} />
                <Separator />
                <MetaRow label="State directory" value={status.state_dir || '—'} mono copy />
                <MetaRow label="Control socket" value={status.control_path || '—'} mono copy />
              </CardContent>
            </Card>

            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <ShieldCheck className="size-4 text-emerald-600 dark:text-emerald-300" />
                  Read-only preview
                </CardTitle>
                <CardDescription>
                  This console is an observer, not a configuration surface.
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-4 text-sm">
                <div className="flex items-start gap-3">
                  <LockKeyhole className="mt-0.5 size-4 shrink-0 text-emerald-600 dark:text-emerald-300" />
                  <p className="text-muted-foreground">
                    All state is read through the local Unix control socket. The web process
                    never edits routes, addresses, NAT rules or firewall state.
                  </p>
                </div>
                <div className="flex items-start gap-3">
                  <Clock3 className="mt-0.5 size-4 shrink-0 text-emerald-600 dark:text-emerald-300" />
                  <p className="text-muted-foreground">
                    Overview, NAT and connections auto-refresh; System loads on demand.
                  </p>
                </div>
                <div className="flex items-start gap-3">
                  <FileText className="mt-0.5 size-4 shrink-0 text-emerald-600 dark:text-emerald-300" />
                  <p className="text-muted-foreground">
                    Configuration changes still belong to the vRouter CLI and daemon journal.
                  </p>
                </div>
                <div className="flex flex-wrap gap-2 pt-1">
                  <Badge variant="outline">loopback only</Badge>
                  <Badge variant="outline">session protected</Badge>
                  <Badge variant="outline">no host mutation</Badge>
                </div>
              </CardContent>
            </Card>
          </div>

          <Alert>
            <Info />
            <AlertTitle>Preview scope</AlertTitle>
            <AlertDescription>
              The web admin is an opt-in post-v1 preview. TLS termination and remote access are
              intentionally out of scope; bind it to loopback and use an SSH tunnel or a
              separately secured reverse proxy if you need remote access.
            </AlertDescription>
          </Alert>
        </>
      ) : null}
    </div>
  )
}

function InfoCard({
  icon,
  label,
  value,
}: {
  icon: ReactNode
  label: string
  value: string
}) {
  return (
    <Card>
      <CardContent className="flex items-center gap-3 p-5">
        <div className="flex size-9 items-center justify-center rounded-lg bg-emerald-500/10 text-emerald-600 dark:text-emerald-300">
          {icon}
        </div>
        <div className="min-w-0">
          <p className="text-xs font-medium uppercase tracking-wide text-muted-foreground">{label}</p>
          <p className="truncate font-mono text-sm" title={value}>
            {value}
          </p>
        </div>
      </CardContent>
    </Card>
  )
}

function MetaRow({
  label,
  value,
  mono = false,
  copy = false,
}: {
  label: string
  value: string
  mono?: boolean
  copy?: boolean
}) {
  return (
    <div className="flex items-start justify-between gap-3">
      <span className="shrink-0 text-muted-foreground">{label}</span>
      <span className={mono ? 'flex min-w-0 items-center gap-1 font-mono text-xs' : 'text-right'}>
        <span className="truncate" title={value}>
          {value}
        </span>
        {copy && value !== '—' ? <CopyButton value={value} label={`Copy ${label}`} /> : null}
      </span>
    </div>
  )
}
