import {
  ArrowLeftRight,
  Cable,
  ChevronDown,
  LayoutDashboard,
  LogOut,
  Menu,
  Router,
  Settings,
  ShieldCheck,
} from 'lucide-react'
import { useState } from 'react'
import type { ComponentType } from 'react'
import { NavLink, Outlet, useLocation } from 'react-router-dom'
import { Avatar, AvatarFallback } from '@/components/ui/avatar'
import { Badge } from '@/components/ui/badge'
import {
  Breadcrumb,
  BreadcrumbItem,
  BreadcrumbList,
  BreadcrumbPage,
  BreadcrumbSeparator,
} from '@/components/ui/breadcrumb'
import { Button } from '@/components/ui/button'
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu'
import {
  Sheet,
  SheetContent,
  SheetHeader,
  SheetTitle,
  SheetTrigger,
} from '@/components/ui/sheet'
import { ThemeToggle } from '@/components/theme-toggle'
import { cn } from '@/lib/utils'

type NavItem = {
  to: string
  label: string
  icon: ComponentType<{ className?: string }>
}

const navGroups: { label: string; items: NavItem[] }[] = [
  {
    label: 'Monitor',
    items: [{ to: '/overview', label: 'Overview', icon: LayoutDashboard }],
  },
  {
    label: 'Network',
    items: [
      { to: '/nat', label: 'NAT', icon: ArrowLeftRight },
      { to: '/connections', label: 'Connections', icon: Cable },
    ],
  },
  {
    label: 'System',
    items: [{ to: '/system', label: 'System', icon: Settings }],
  },
]

const allItems = navGroups.flatMap((group) => group.items)

function Brand() {
  return (
    <div className="flex items-center gap-3">
      <div className="flex size-10 items-center justify-center rounded-xl bg-emerald-500 text-emerald-950 shadow-lg shadow-emerald-950/30">
        <Router className="size-5" />
      </div>
      <div className="leading-tight">
        <div className="font-semibold tracking-tight text-white">vRouter</div>
        <div className="text-xs text-sidebar-foreground/60">Admin preview</div>
      </div>
    </div>
  )
}

function SidebarNav({ onNavigate }: { onNavigate?: () => void }) {
  return (
    <nav className="flex-1 space-y-6 overflow-y-auto px-3 py-4">
      {navGroups.map((group) => (
        <div key={group.label} className="space-y-1">
          <p className="px-3 text-[11px] font-medium uppercase tracking-widest text-sidebar-foreground/45">
            {group.label}
          </p>
          {group.items.map((item) => (
            <NavLink
              key={item.to}
              to={item.to}
              onClick={onNavigate}
              className={({ isActive }) =>
                cn(
                  'group flex items-center gap-3 rounded-lg px-3 py-2 text-sm font-medium text-sidebar-foreground/75 transition-colors hover:bg-sidebar-accent hover:text-sidebar-accent-foreground',
                  isActive &&
                    'bg-sidebar-accent text-sidebar-accent-foreground shadow-sm ring-1 ring-white/5',
                )
              }
            >
              <item.icon className="size-4 text-sidebar-foreground/55 transition-colors group-hover:text-emerald-300" />
              {item.label}
            </NavLink>
          ))}
        </div>
      ))}
    </nav>
  )
}

function SidebarFooter() {
  return (
    <div className="border-t border-sidebar-border p-4">
      <div className="flex items-center gap-2 text-xs text-sidebar-foreground/65">
        <ShieldCheck className="size-3.5 text-emerald-400" />
        Read-only control plane
      </div>
      <p className="mt-1 text-[11px] leading-relaxed text-sidebar-foreground/40">
        State is read through the local Unix socket.
      </p>
    </div>
  )
}

export function AppShell({ onSignOut }: { onSignOut: () => Promise<void> }) {
  const location = useLocation()
  const [mobileOpen, setMobileOpen] = useState(false)
  const current =
    allItems.find((item) => location.pathname === item.to) ??
    allItems.find((item) => location.pathname.startsWith(`${item.to}/`))

  return (
    <div className="min-h-screen bg-background">
      <aside className="fixed inset-y-0 left-0 z-30 hidden w-64 flex-col border-r border-sidebar-border bg-sidebar text-sidebar-foreground lg:flex">
        <div className="flex h-16 items-center border-b border-sidebar-border px-5">
          <Brand />
        </div>
        <SidebarNav />
        <SidebarFooter />
      </aside>

      <Sheet open={mobileOpen} onOpenChange={setMobileOpen}>
        <div className="lg:hidden">
          <SheetTrigger asChild>
            <Button
              variant="ghost"
              size="icon"
              className="fixed left-3 top-3 z-40"
              aria-label="Open navigation"
            >
              <Menu className="size-5" />
            </Button>
          </SheetTrigger>
        </div>
        <SheetContent
          side="left"
          className="w-72 gap-0 border-sidebar-border bg-sidebar p-0 text-sidebar-foreground"
        >
          <SheetHeader className="h-16 justify-center border-b border-sidebar-border px-5">
            <SheetTitle className="sr-only">Navigation</SheetTitle>
            <Brand />
          </SheetHeader>
          <SidebarNav onNavigate={() => setMobileOpen(false)} />
          <SidebarFooter />
        </SheetContent>
      </Sheet>

      <div className="flex min-h-screen flex-col lg:pl-64">
        <header className="sticky top-0 z-20 flex h-16 items-center gap-3 border-b bg-background/85 px-4 pl-14 backdrop-blur supports-[backdrop-filter]:bg-background/70 sm:px-6 lg:pl-6">
          <Breadcrumb className="min-w-0">
            <BreadcrumbList>
              <BreadcrumbItem className="hidden sm:inline-flex">
                <span className="text-muted-foreground">vRouter</span>
              </BreadcrumbItem>
              <BreadcrumbSeparator className="hidden sm:block" />
              <BreadcrumbItem>
                <BreadcrumbPage>{current?.label ?? 'Admin'}</BreadcrumbPage>
              </BreadcrumbItem>
            </BreadcrumbList>
          </Breadcrumb>

          <div className="ml-auto flex items-center gap-1.5">
            <Badge
              variant="outline"
              className="hidden border-emerald-500/25 bg-emerald-500/10 text-emerald-700 sm:inline-flex dark:text-emerald-300"
            >
              Read-only
            </Badge>
            <ThemeToggle />
            <DropdownMenu>
              <DropdownMenuTrigger asChild>
                <Button variant="ghost" className="h-9 gap-2 px-2">
                  <Avatar className="size-7">
                    <AvatarFallback className="bg-emerald-500/15 text-xs font-semibold text-emerald-700 dark:text-emerald-300">
                      A
                    </AvatarFallback>
                  </Avatar>
                  <span className="hidden text-sm font-medium sm:inline">admin</span>
                  <ChevronDown className="size-3.5 text-muted-foreground" />
                </Button>
              </DropdownMenuTrigger>
              <DropdownMenuContent align="end" className="w-48">
                <DropdownMenuLabel>
                  <div className="text-sm font-medium">admin</div>
                  <div className="text-xs font-normal text-muted-foreground">
                    Local session
                  </div>
                </DropdownMenuLabel>
                <DropdownMenuSeparator />
                <DropdownMenuItem onClick={() => void onSignOut()}>
                  <LogOut className="size-4" />
                  Sign out
                </DropdownMenuItem>
              </DropdownMenuContent>
            </DropdownMenu>
          </div>
        </header>

        <main className="flex-1">
          <div className="mx-auto w-full max-w-7xl px-4 py-6 sm:px-6 lg:px-8 lg:py-8">
            <Outlet />
          </div>
        </main>
      </div>
    </div>
  )
}
