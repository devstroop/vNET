import type { ReactNode } from 'react'
import {
  Activity,
  ArrowDownRight,
  ArrowUpRight,
  Clock3,
  Gauge,
  Network,
  RefreshCw,
  ShieldAlert,
  ShieldCheck,
  Waypoints,
} from 'lucide-react'
import { getStatus } from '@/api/client'
import { CopyButton } from '@/components/copy-button'
import { PageHeader } from '@/components/page-header'
import { ErrorState, LoadingCards } from '@/components/states'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table'
import { useResource } from '@/hooks/use-resource'
import { formatDateTime, formatDuration, formatNumber, formatRelative } from '@/lib/format'

export function OverviewPage() {
  const { data, error, loading, refresh, updatedAt } = useResource(getStatus, 5000)
  const status = data?.status

  return (
    <div className="space-y-6">
      <PageHeader
        title="Overview"
        description="A live snapshot of forwarding, connection tracking and NAT activity."
        actions={
          <>
            <Badge
              variant="outline"
              className="hidden gap-1.5 border-emerald-500/25 bg-emerald-500/10 text-emerald-700 sm:inline-flex dark:text-emerald-300"
            >
              <span className="relative flex size-2">
                <span className="absolute inline-flex size-full animate-ping rounded-full bg-emerald-500 opacity-60" />
                <span className="relative inline-flex size-2 rounded-full bg-emerald-500" />
              </span>
              Live
            </Badge>
            <Button variant="outline" size="sm" onClick={() => void refresh()}>
              <RefreshCw className={loading ? 'size-4 animate-spin' : 'size-4'} />
              Refresh
            </Button>
          </>
        }
      />

      {error && !status ? <ErrorState message={error} onRetry={() => void refresh()} /> : null}
      {error && status ? (
        <ErrorState message={`Live refresh failed: ${error}`} onRetry={() => void refresh()} />
      ) : null}
      {loading && !status ? <LoadingCards count={6} /> : null}

      {status ? (
        <>
          <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-3">
            <StatCard
              label="Ports"
              value={formatNumber(status.ports)}
              hint="Attached datapath ports"
              icon={<Network className="size-4" />}
            />
            <StatCard
              label="Uptime"
              value={formatDuration(status.uptime_ms)}
              hint={status.started_ms ? `Since ${formatDateTime(status.started_ms)}` : 'Daemon start time unavailable'}
              icon={<Clock3 className="size-4" />}
            />
            <StatCard
              label="Forwarded"
              value={formatNumber(status.counters.forwarded + status.counters.bridged)}
              hint={`${formatNumber(status.counters.forwarded)} L3 · ${formatNumber(status.counters.bridged)} bridged`}
              icon={<ArrowUpRight className="size-4" />}
            />
            <StatCard
              label="Dropped"
              value={formatNumber(status.counters.dropped + status.counters.firewall_dropped)}
              hint={`${formatNumber(status.counters.firewall_dropped)} by firewall`}
              icon={<ArrowDownRight className="size-4" />}
              tone={
                status.counters.dropped + status.counters.firewall_dropped > 0
                  ? 'warning'
                  : 'default'
              }
            />
            <StatCard
              label="Conntrack hits"
              value={formatNumber(status.counters.conntrack_hits)}
              hint={`${formatNumber(status.counters.conntrack_created)} flows created`}
              icon={<Gauge className="size-4" />}
            />
            <StatCard
              label="NAT packets"
              value={formatNumber(status.counters.snat_packets + status.counters.dnat_packets)}
              hint={`${formatNumber(status.counters.snat_packets)} SNAT · ${formatNumber(status.counters.dnat_packets)} DNAT`}
              icon={<Waypoints className="size-4" />}
            />
          </div>

          <div className="grid gap-4 lg:grid-cols-3">
            <Card className="lg:col-span-2">
              <CardHeader>
                <CardTitle>Traffic counters</CardTitle>
                <CardDescription>Cumulative counters since the daemon started.</CardDescription>
              </CardHeader>
              <CardContent>
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>Counter</TableHead>
                      <TableHead className="text-right">Value</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {counterRows(status.counters).map(([label, value]) => (
                      <TableRow key={label}>
                        <TableCell className="text-muted-foreground">{label}</TableCell>
                        <TableCell className="text-right font-mono tabular-nums">
                          {formatNumber(value)}
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </CardContent>
            </Card>

            <div className="space-y-4">
              <HealthCard
                drops={
                  status.counters.dropped +
                  status.counters.firewall_dropped +
                  status.counters.ipv6_dropped +
                  status.counters.storm_dropped
                }
                tableFull={status.counters.conntrack_table_full}
              />

              <Card>
                <CardHeader>
                  <CardTitle>Runtime</CardTitle>
                  <CardDescription>Instance metadata from the control plane.</CardDescription>
                </CardHeader>
                <CardContent className="space-y-3 text-sm">
                  <MetaRow label="Instance" value={status.instance || '—'} />
                  <MetaRow label="Version" value={status.version || '—'} />
                  <MetaRow label="PID" value={formatNumber(status.pid)} />
                  <MetaRow label="Ports" value={formatNumber(status.ports)} />
                  <MetaRow label="Updated" value={formatDateTime(status.updated_ms)} />
                  <MetaRow label="State dir" value={status.state_dir || '—'} mono copy />
                  <MetaRow label="Control" value={status.control_path || '—'} mono copy />
                </CardContent>
              </Card>
            </div>
          </div>

          <p className="text-xs text-muted-foreground">
            Last refreshed {updatedAt ? formatRelative(updatedAt) : '—'} · auto-refreshes every 5s
          </p>
        </>
      ) : null}
    </div>
  )
}

function StatCard({
  label,
  value,
  hint,
  icon,
  tone = 'default',
}: {
  label: string
  value: string
  hint: string
  icon: ReactNode
  tone?: 'default' | 'warning'
}) {
  return (
    <Card>
      <CardContent className="p-5">
        <div className="flex items-start justify-between gap-3">
          <div className="space-y-1">
            <p className="text-xs font-medium uppercase tracking-wide text-muted-foreground">
              {label}
            </p>
            <p className="text-2xl font-semibold tracking-tight tabular-nums">{value}</p>
          </div>
          <div
            className={
              tone === 'warning'
                ? 'flex size-9 items-center justify-center rounded-lg bg-amber-500/10 text-amber-600 dark:text-amber-300'
                : 'flex size-9 items-center justify-center rounded-lg bg-emerald-500/10 text-emerald-600 dark:text-emerald-300'
            }
          >
            {icon}
          </div>
        </div>
        <p className="mt-3 text-xs text-muted-foreground">{hint}</p>
      </CardContent>
    </Card>
  )
}

function HealthCard({ drops, tableFull }: { drops: number; tableFull: number }) {
  if (tableFull > 0) {
    return (
      <Card className="border-rose-500/30 bg-rose-500/5">
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-rose-700 dark:text-rose-300">
            <ShieldAlert className="size-4" />
            Conntrack table full
          </CardTitle>
          <CardDescription>
            {formatNumber(tableFull)} new flows were dropped because the table reached capacity.
          </CardDescription>
        </CardHeader>
      </Card>
    )
  }

  if (drops > 0) {
    return (
      <Card className="border-amber-500/30 bg-amber-500/5">
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-amber-700 dark:text-amber-300">
            <Activity className="size-4" />
            Drops recorded
          </CardTitle>
          <CardDescription>
            {formatNumber(drops)} packets were dropped across forwarding, firewall, IPv6 and
            storm-control paths.
          </CardDescription>
        </CardHeader>
      </Card>
    )
  }

  return (
    <Card className="border-emerald-500/30 bg-emerald-500/5">
      <CardHeader>
        <CardTitle className="flex items-center gap-2 text-emerald-700 dark:text-emerald-300">
          <ShieldCheck className="size-4" />
          No drops recorded
        </CardTitle>
        <CardDescription>
          Forwarding, firewall, IPv6 and storm-control counters are all clear.
        </CardDescription>
      </CardHeader>
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

function counterRows(counters: {
  forwarded: number
  bridged: number
  dropped: number
  firewall_dropped: number
  conntrack_created: number
  conntrack_hits: number
  snat_packets: number
  dnat_packets: number
  dhcp_acks: number
  ipv6_forwarded: number
}): [string, number][] {
  return [
    ['Forwarded (L3)', counters.forwarded],
    ['Bridged (L2)', counters.bridged],
    ['Dropped', counters.dropped],
    ['Firewall dropped', counters.firewall_dropped],
    ['Conntrack created', counters.conntrack_created],
    ['Conntrack hits', counters.conntrack_hits],
    ['SNAT packets', counters.snat_packets],
    ['DNAT packets', counters.dnat_packets],
    ['DHCP ACKs', counters.dhcp_acks],
    ['IPv6 forwarded', counters.ipv6_forwarded],
  ]
}
