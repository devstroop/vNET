import { ArrowLeftRight, Network, RefreshCw, Waypoints } from 'lucide-react'
import { getNat } from '@/api/client'
import { PageHeader } from '@/components/page-header'
import { EmptyState, ErrorState, LoadingCards } from '@/components/states'
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
import { formatNumber } from '@/lib/format'

export function NatPage() {
  const { data, error, loading, refresh } = useResource(getNat, 10_000)
  const nat = data?.nat

  return (
    <div className="space-y-6">
      <PageHeader
        title="NAT"
        description="Source NAT and port-forwarding rules currently installed by the control plane."
        actions={
          <Button variant="outline" size="sm" onClick={() => void refresh()}>
            <RefreshCw className={loading ? 'size-4 animate-spin' : 'size-4'} />
            Refresh
          </Button>
        }
      />

      {error && !nat ? <ErrorState message={error} onRetry={() => void refresh()} /> : null}
      {error && nat ? (
        <ErrorState message={`Live refresh failed: ${error}`} onRetry={() => void refresh()} />
      ) : null}
      {loading && !nat ? <LoadingCards count={2} /> : null}

      {nat ? (
        <>
          <div className="grid gap-4 sm:grid-cols-2">
            <Card>
              <CardContent className="flex items-center gap-4 p-5">
                <div className="flex size-10 items-center justify-center rounded-lg bg-emerald-500/10 text-emerald-600 dark:text-emerald-300">
                  <Waypoints className="size-5" />
                </div>
                <div>
                  <p className="text-xs font-medium uppercase tracking-wide text-muted-foreground">
                    Masquerade rules
                  </p>
                  <p className="text-2xl font-semibold tabular-nums">{formatNumber(nat.snat.length)}</p>
                </div>
              </CardContent>
            </Card>
            <Card>
              <CardContent className="flex items-center gap-4 p-5">
                <div className="flex size-10 items-center justify-center rounded-lg bg-sky-500/10 text-sky-600 dark:text-sky-300">
                  <ArrowLeftRight className="size-5" />
                </div>
                <div>
                  <p className="text-xs font-medium uppercase tracking-wide text-muted-foreground">
                    Port forwards
                  </p>
                  <p className="text-2xl font-semibold tabular-nums">
                    {formatNumber(nat.port_forward.length)}
                  </p>
                </div>
              </CardContent>
            </Card>
          </div>

          <Card>
            <CardHeader>
              <CardTitle>Source NAT</CardTitle>
              <CardDescription>
                Outbound interfaces and the address used for masquerading.
              </CardDescription>
            </CardHeader>
            <CardContent>
              {nat.snat.length === 0 ? (
                <EmptyState
                  icon={<Waypoints className="size-5" />}
                  title="No masquerade rules"
                  description="Source NAT rules appear here after they are configured on the daemon."
                />
              ) : (
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>Outbound interface</TableHead>
                      <TableHead>Translated address</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {nat.snat.map((rule, index) => (
                      <TableRow key={`${rule.out}-${rule.addr}-${index}`}>
                        <TableCell className="font-medium">{rule.out || '—'}</TableCell>
                        <TableCell className="font-mono text-sm">{rule.addr || '—'}</TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              )}
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle>Port forwards</CardTitle>
              <CardDescription>
                External ports redirected to hosts behind the router.
              </CardDescription>
            </CardHeader>
            <CardContent>
              {nat.port_forward.length === 0 ? (
                <EmptyState
                  icon={<Network className="size-5" />}
                  title="No port forwards"
                  description="Destination NAT rules appear here after they are configured on the daemon."
                />
              ) : (
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>Protocol</TableHead>
                      <TableHead>External port</TableHead>
                      <TableHead>Destination</TableHead>
                      <TableHead className="hidden sm:table-cell">Ingress</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {nat.port_forward.map((rule, index) => (
                      <TableRow key={`${rule.proto}-${rule.ext_port}-${index}`}>
                        <TableCell>
                          <Badge variant="outline" className="uppercase">
                            {rule.proto || 'any'}
                          </Badge>
                        </TableCell>
                        <TableCell className="font-mono text-sm tabular-nums">
                          {rule.ext_port}
                        </TableCell>
                        <TableCell className="font-mono text-sm">
                          {rule.to_addr}:{rule.to_port}
                        </TableCell>
                        <TableCell className="hidden text-muted-foreground sm:table-cell">
                          {rule.ingress || 'any'}
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              )}
            </CardContent>
          </Card>
        </>
      ) : null}
    </div>
  )
}
