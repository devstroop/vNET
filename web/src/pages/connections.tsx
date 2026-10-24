import { Cable, RefreshCw, Search } from 'lucide-react'
import { useMemo, useState } from 'react'
import { getConntrack } from '@/api/client'
import type { ConntrackEntry } from '@/api/types'
import { PageHeader } from '@/components/page-header'
import { EmptyState, ErrorState, LoadingTable } from '@/components/states'
import { StatusBadge } from '@/components/status-badge'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Switch } from '@/components/ui/switch'
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table'
import { Tabs, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { useResource } from '@/hooks/use-resource'
import { formatBytes, formatEndpoint, formatNumber, formatRelative } from '@/lib/format'

const knownStates = new Set(['established', 'new', 'related', 'closed'])

export function ConnectionsPage() {
  const [live, setLive] = useState(true)
  const [query, setQuery] = useState('')
  const [stateFilter, setStateFilter] = useState('all')
  const { data, error, loading, refresh, updatedAt } = useResource(
    getConntrack,
    live ? 3000 : 0,
  )
  const conntrack = data?.conntrack
  const entries = useMemo(() => conntrack?.entries ?? [], [conntrack])

  const filtered = useMemo(() => {
    const needle = query.trim().toLowerCase()
    return entries.filter((entry) => {
      const state = entry.state.toLowerCase()
      const stateMatches =
        stateFilter === 'all' ||
        (stateFilter === 'other' ? !knownStates.has(state) : state === stateFilter)
      if (!stateMatches) return false
      if (!needle) return true
      return [
        entry.proto,
        entry.state,
        entry.src,
        entry.dst,
        entry.translated_src ?? '',
        entry.translated_dst ?? '',
      ]
        .join(' ')
        .toLowerCase()
        .includes(needle)
    })
  }, [entries, query, stateFilter])

  return (
    <div className="space-y-6">
      <PageHeader
        title="Connections"
        description="Live connection-tracking entries, newest state first."
        actions={
          <>
            <div className="flex items-center gap-2 rounded-lg border px-3 py-1.5">
              <Switch id="live" checked={live} onCheckedChange={setLive} />
              <Label htmlFor="live" className="text-xs text-muted-foreground">
                Auto-refresh
              </Label>
            </div>
            <Button variant="outline" size="sm" onClick={() => void refresh()}>
              <RefreshCw className={loading ? 'size-4 animate-spin' : 'size-4'} />
              Refresh
            </Button>
          </>
        }
      />

      {error && !conntrack ? <ErrorState message={error} onRetry={() => void refresh()} /> : null}
      {error && conntrack ? (
        <ErrorState message={`Live refresh failed: ${error}`} onRetry={() => void refresh()} />
      ) : null}
      {loading && !conntrack ? <LoadingTable rows={8} /> : null}

      {conntrack ? (
        <>
          <div className="grid gap-4 sm:grid-cols-3">
            <Summary label="Total flows" value={formatNumber(conntrack.total)} />
            <Summary label="Returned" value={formatNumber(conntrack.returned)} />
            <Summary
              label="Visible"
              value={formatNumber(filtered.length)}
              hint={
                conntrack.total > conntrack.returned
                  ? `Showing the first ${formatNumber(conntrack.returned)} of ${formatNumber(conntrack.total)}`
                  : undefined
              }
            />
          </div>

          <Card>
            <CardHeader className="gap-4">
              <div className="flex flex-col gap-1">
                <CardTitle>Connection table</CardTitle>
                <CardDescription>
                  Search by address, protocol or state. Timestamps are relative to now.
                </CardDescription>
              </div>
              <div className="flex flex-col gap-3 lg:flex-row lg:items-center lg:justify-between">
                <Tabs value={stateFilter} onValueChange={setStateFilter}>
                  <TabsList className="flex-wrap">
                    <TabsTrigger value="all">All</TabsTrigger>
                    <TabsTrigger value="established">Established</TabsTrigger>
                    <TabsTrigger value="new">New</TabsTrigger>
                    <TabsTrigger value="related">Related</TabsTrigger>
                    <TabsTrigger value="other">Other</TabsTrigger>
                  </TabsList>
                </Tabs>
                <div className="relative w-full lg:max-w-xs">
                  <Search className="pointer-events-none absolute left-2.5 top-1/2 size-4 -translate-y-1/2 text-muted-foreground" />
                  <Input
                    value={query}
                    onChange={(event) => setQuery(event.target.value)}
                    placeholder="Filter connections…"
                    className="pl-8"
                    aria-label="Filter connections"
                  />
                </div>
              </div>
            </CardHeader>
            <CardContent>
              {entries.length === 0 ? (
                <EmptyState
                  icon={<Cable className="size-5" />}
                  title="No active connections"
                  description="Connection-tracking entries appear here once traffic passes through the router."
                />
              ) : filtered.length === 0 ? (
                <EmptyState
                  icon={<Search className="size-5" />}
                  title="No matching connections"
                  description="Adjust the search text or state filter to see more entries."
                />
              ) : (
                <div className="-mx-2 overflow-x-auto">
                  <Table>
                    <TableHeader>
                      <TableRow>
                        <TableHead>Protocol</TableHead>
                        <TableHead>State</TableHead>
                        <TableHead>Source</TableHead>
                        <TableHead>Destination</TableHead>
                        <TableHead className="hidden lg:table-cell">Translation</TableHead>
                        <TableHead className="hidden text-right md:table-cell">Packets</TableHead>
                        <TableHead className="hidden text-right md:table-cell">Bytes</TableHead>
                        <TableHead className="text-right">Last seen</TableHead>
                      </TableRow>
                    </TableHeader>
                    <TableBody>
                      {filtered.map((entry) => (
                        <TableRow key={entryKey(entry)}>
                          <TableCell>
                            <Badge variant="outline" className="uppercase">
                              {entry.proto || '—'}
                            </Badge>
                          </TableCell>
                          <TableCell>
                            <StatusBadge state={entry.state} />
                          </TableCell>
                          <TableCell className="font-mono text-xs sm:text-sm">
                            {formatEndpoint(entry.src, entry.sport)}
                          </TableCell>
                          <TableCell className="font-mono text-xs sm:text-sm">
                            {formatEndpoint(entry.dst, entry.dport)}
                          </TableCell>
                          <TableCell className="hidden max-w-56 truncate font-mono text-xs text-muted-foreground lg:table-cell">
                            {translation(entry)}
                          </TableCell>
                          <TableCell className="hidden text-right font-mono text-xs tabular-nums md:table-cell">
                            {formatNumber(entry.packets)}
                          </TableCell>
                          <TableCell className="hidden text-right font-mono text-xs tabular-nums md:table-cell">
                            {formatBytes(entry.bytes)}
                          </TableCell>
                          <TableCell
                            className="text-right text-xs text-muted-foreground"
                            title={entry.last_seen_ms ? new Date(entry.last_seen_ms).toLocaleString() : undefined}
                          >
                            {formatRelative(entry.last_seen_ms)}
                          </TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                </div>
              )}
            </CardContent>
          </Card>

          <p className="text-xs text-muted-foreground">
            {live
              ? `Auto-refreshing every 3s · last update ${updatedAt ? formatRelative(updatedAt) : '—'}`
              : 'Auto-refresh paused'}
          </p>
        </>
      ) : null}
    </div>
  )
}

function Summary({
  label,
  value,
  hint,
}: {
  label: string
  value: string
  hint?: string
}) {
  return (
    <Card>
      <CardContent className="p-5">
        <p className="text-xs font-medium uppercase tracking-wide text-muted-foreground">{label}</p>
        <p className="mt-1 text-2xl font-semibold tabular-nums">{value}</p>
        {hint ? <p className="mt-1 text-xs text-muted-foreground">{hint}</p> : null}
      </CardContent>
    </Card>
  )
}

function translation(entry: ConntrackEntry): string {
  const parts: string[] = []
  if (entry.translated_src) {
    parts.push(`src ${formatEndpoint(entry.translated_src, entry.translated_sport)}`)
  }
  if (entry.translated_dst) {
    parts.push(`dst ${formatEndpoint(entry.translated_dst, entry.translated_dport)}`)
  }
  return parts.length ? parts.join(' · ') : '—'
}

function entryKey(entry: ConntrackEntry): string {
  return [
    entry.proto,
    entry.src,
    entry.sport,
    entry.dst,
    entry.dport,
    entry.created_ms,
  ].join(':')
}
