import { Badge } from '@/components/ui/badge'
import { cn } from '@/lib/utils'

const styles: Record<string, string> = {
  established:
    'border-emerald-500/25 bg-emerald-500/10 text-emerald-700 dark:text-emerald-300',
  new: 'border-sky-500/25 bg-sky-500/10 text-sky-700 dark:text-sky-300',
  related: 'border-amber-500/25 bg-amber-500/10 text-amber-700 dark:text-amber-300',
  closed: 'border-border bg-muted text-muted-foreground',
  invalid: 'border-rose-500/25 bg-rose-500/10 text-rose-700 dark:text-rose-300',
}

export function StatusBadge({ state }: { state: string }) {
  const label = state || 'unknown'
  return (
    <Badge
      variant="outline"
      className={cn('font-medium capitalize', styles[label.toLowerCase()] ?? styles.closed)}
    >
      {label}
    </Badge>
  )
}
