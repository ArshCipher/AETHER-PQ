import { Link, useRouterState } from "@tanstack/react-router";
import {
  LayoutDashboard, Radar, Plane, LineChart, ShieldCheck, Search, HelpCircle,
  Settings, ChevronRight, BookOpen, Lock, Cpu, Network, ScrollText, Menu, X,
  LogOut, UserCheck, KeyRound, AlertTriangle, Video
} from "lucide-react";
import { useEffect, useState, type ReactNode } from "react";
import { LiveClock, LiveDot, NotificationCenter, PacketFlow } from "@/components/live";
import { useTicker } from "@/hooks/use-live";
import { useWebSocketContext } from "@/components/websocket-provider";
import { cn } from "@/lib/utils";

import { Activity } from "lucide-react";

const NAV: { group: string; items: { to: string; label: string; icon: any }[] }[] = [
  {
    group: "Command",
    items: [
      { to: "/", label: "Executive Dashboard", icon: LayoutDashboard },
      { to: "/mission", label: "Mission Control", icon: Radar },
      { to: "/fleet", label: "UAV Fleet", icon: Plane },
      { to: "/telemetry", label: "Telemetry", icon: LineChart },
      { to: "/recordings", label: "Mission Recordings", icon: Video },
    ],
  },
  {
    group: "Security",
    items: [
      { to: "/security", label: "Security Center", icon: Lock },
      { to: "/acpe", label: "ACPE Policy Engine", icon: Cpu },
      { to: "/treekem", label: "TreeKEM Management", icon: Network },
    ],
  },
  {
    group: "Diagnostics",
    items: [
      { to: "/logs", label: "Logs", icon: ScrollText },
      { to: "/health", label: "System Health", icon: Activity },
      { to: "/query", label: "On-Demand Query", icon: Search },
    ],
  },
  {
    group: "Reference",
    items: [
      { to: "/system", label: "Design System", icon: BookOpen },
      { to: "/about", label: "About Engine", icon: HelpCircle },
    ],
  },
];

function SideNav({ pathname, onNavigate }: { pathname: string; onNavigate?: () => void }) {
  return (
    <nav className="flex h-full flex-col overflow-y-auto p-3" aria-label="Primary">
      {NAV.map((g) => (
        <div key={g.group} className="mb-5">
          <div className="text-overline px-2 pb-2">{g.group}</div>
          <ul className="space-y-0.5">
            {g.items.map((it) => {
              const active = pathname === it.to;
              const Icon = it.icon;
              return (
                <li key={it.to}>
                  <Link
                    to={it.to}
                    onClick={onNavigate}
                    aria-current={active ? "page" : undefined}
                    className={cn(
                      "group relative flex items-center gap-2.5 rounded-md px-2.5 py-1.5 text-[13px] transition-colors",
                      "focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring",
                      active
                        ? "font-medium text-primary"
                        : "text-foreground/80 hover:bg-surface-2",
                    )}
                    style={active ? { background: "color-mix(in oklab, var(--color-primary) 8%, transparent)" } : undefined}
                  >
                    {active && (
                      <span
                        aria-hidden="true"
                        className="absolute left-0 top-1/2 h-4 w-[2px] -translate-y-1/2 rounded-r-full bg-primary"
                      />
                    )}
                    <Icon className={cn("h-4 w-4", active ? "text-primary" : "text-muted-foreground")} strokeWidth={2} />
                    <span className="flex-1">{it.label}</span>
                    {active && <ChevronRight className="h-3.5 w-3.5 text-primary" />}
                  </Link>
                </li>
              );
            })}
          </ul>
        </div>
      ))}
      <div className="mt-auto rounded-md border border-border bg-surface-2 p-3 text-[11px] text-muted-foreground">
        <div className="text-overline mb-1">System</div>
        <div className="text-tabular">Build 2026.07.08-a3f2</div>
        <div className="text-tabular">Region · IN-SOUTH-1</div>
        <div className="mt-2 flex items-center gap-1.5">
          <LiveDot tone="success" />
          <span>All services operational</span>
        </div>
      </div>
    </nav>
  );
}

/** Tiny live event ticker under the header. Cycles through recent events. */
function EventTicker() {
  const { data } = useWebSocketContext();
  const tick = useTicker(4200);
  const events = data?.recentActivity?.slice(0, 6) || [];
  const toneMap = { critical: "critical", warning: "warning", success: "success", info: "info" } as const;
  
  if (events.length === 0) {
    return (
      <div className="hidden items-center gap-3 border-b border-border bg-surface px-6 py-1.5 text-[11.5px] md:flex">
        <span className="text-overline">Live Feed</span>
        <span className="h-3 w-px bg-border" />
        <div className="flex min-w-0 flex-1 items-center gap-2">
          <span className="text-muted-foreground">Waiting for live data feed...</span>
        </div>
      </div>
    );
  }

  const e = events[tick % events.length];
  return (
    <div className="hidden items-center gap-3 border-b border-border bg-surface px-6 py-1.5 text-[11.5px] md:flex">
      <span className="text-overline">Live Feed</span>
      <span className="h-3 w-px bg-border" />
      <div className="flex min-w-0 flex-1 items-center gap-2" key={tick}>
        <LiveDot tone={toneMap[e.severity as keyof typeof toneMap] || "info"} />
        <span className="text-tabular text-[10.5px] text-muted-foreground">{e.ts}</span>
        <span className="text-tabular text-[10px] uppercase tracking-wider text-muted-foreground">{e.actor}</span>
        <span className="animate-fade-in-up truncate text-foreground/90">{e.message}</span>
      </div>
      <div className="w-24"><PacketFlow tone="primary" /></div>
    </div>
  );
}

export function AppShell({
  title, eyebrow, actions, breadcrumbs, children,
}: {
  title: string;
  eyebrow?: string;
  actions?: ReactNode;
  breadcrumbs?: { label: string; to?: string }[];
  children: ReactNode;
}) {
  const pathname = useRouterState({ select: (s) => s.location.pathname });
  const [mobileOpen, setMobileOpen] = useState(false);
  const { authState, login, logout } = useWebSocketContext();

  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");

  useEffect(() => { setMobileOpen(false); }, [pathname]);

  const handleLoginSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (username.trim() && password.trim()) {
      login(username.trim(), password.trim());
    }
  };

  // 1. Render Login Card Overlay if unauthenticated
  if (!authState.authenticated) {
    return (
      <div className="flex min-h-screen items-center justify-center bg-surface p-4 text-foreground">
        <div className="w-full max-w-md rounded-lg border border-border bg-card p-6 shadow-md md:p-8 animate-fade-in-scale">
          <div className="flex flex-col items-center text-center">
            <div className="flex h-12 w-12 items-center justify-center rounded-lg bg-primary text-primary-foreground mb-4">
              <ShieldCheck className="h-6 w-6" strokeWidth={2.5} />
            </div>
            <h1 className="text-[20px] font-bold tracking-tight">AETHER-PQ Swarmlink</h1>
            <p className="mt-1 text-[13px] text-muted-foreground">Post-Quantum UAV Swarm Mission Control Gateway</p>
          </div>

          <form className="mt-8 space-y-4" onSubmit={handleLoginSubmit}>
            {authState.error && (
              <div className="rounded-md bg-critical-muted border border-critical/20 p-3 text-[12px] text-critical flex items-start gap-2">
                <AlertTriangle className="h-4 w-4 shrink-0 mt-0.5" />
                <span>{authState.error}</span>
              </div>
            )}

            <div>
              <label className="text-overline mb-1.5 block" htmlFor="login-username">Operator Username</label>
              <input
                id="login-username"
                type="text"
                required
                disabled={authState.loading}
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                placeholder="e.g. admin, operator"
                className="h-9 w-full rounded-md border border-border bg-surface px-3 text-[13px] outline-none placeholder:text-muted-foreground focus:border-primary focus:ring-1 focus:ring-primary"
              />
            </div>

            <div>
              <label className="text-overline mb-1.5 block" htmlFor="login-password">Secret Password</label>
              <input
                id="login-password"
                type="password"
                required
                disabled={authState.loading}
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder="••••••••"
                className="h-9 w-full rounded-md border border-border bg-surface px-3 text-[13px] outline-none placeholder:text-muted-foreground focus:border-primary focus:ring-1 focus:ring-primary"
              />
            </div>

            <button
              type="submit"
              disabled={authState.loading}
              className="flex h-9 w-full items-center justify-center rounded-md bg-primary text-sm font-medium text-primary-foreground transition-colors hover:bg-primary/90 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring disabled:opacity-50"
            >
              {authState.loading ? (
                <div className="h-4 w-4 animate-spin rounded-full border-2 border-primary-foreground border-t-transparent" />
              ) : (
                "Establish Session"
              )}
            </button>
          </form>

          <div className="mt-6 border-t border-border/80 pt-4 text-center text-[10.5px] text-muted-foreground leading-relaxed">
            The software architecture has been designed for compatibility with <span className="font-mono">ARMv7 Cortex-A9</span> systems running <span className="font-mono">Linux 4.4</span>. Final compatibility and performance validation will be confirmed through execution and benchmarking on the target hardware.
          </div>
        </div>
      </div>
    );
  }

  // 2. Render Full swarmlink console dashboard if authenticated
  const userInitials = authState.username ? authState.username.slice(0, 2).toUpperCase() : "OP";

  return (
    <div className="min-h-dvh bg-surface text-foreground">
      {/* Top bar */}
      <header className="sticky top-0 z-40 border-b border-border bg-background/95 backdrop-blur supports-[backdrop-filter]:bg-background/80">
        <div className="flex h-14 items-center justify-between gap-3 px-4 md:gap-6 md:px-6">
          <div className="flex min-w-0 items-center gap-3">
            <button
              type="button"
              onClick={() => setMobileOpen(true)}
              aria-label="Open navigation"
              className="flex h-8 w-8 items-center justify-center rounded-md border border-border bg-background hover:bg-surface-2 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring lg:hidden"
            >
              <Menu className="h-4 w-4 text-muted-foreground" />
            </button>
            <Link to="/" className="flex items-center gap-3 rounded-md focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring">
              <div className="flex h-8 w-8 items-center justify-center rounded-md bg-primary" aria-hidden="true">
                <ShieldCheck className="h-4 w-4 text-primary-foreground" strokeWidth={2.5} />
              </div>
              <div className="leading-tight">
                <div className="text-[13px] font-semibold tracking-tight">AETHER-PQ</div>
                <div className="text-tabular text-[10.5px] text-muted-foreground">
                  Post-Quantum Mission Control
                </div>
              </div>
            </Link>
            <span className="mx-2 hidden h-6 w-px bg-border md:block" />
            <div className="hidden items-center gap-2 rounded-md border border-border bg-surface-2 px-2.5 py-1 md:flex">
              <LiveDot tone="success" />
              <span className="text-tabular text-[11px] text-muted-foreground">
                LINK · <LiveClock /> · PQ-HYBRID · e-1442
              </span>
            </div>
          </div>

          <div className="flex flex-1 items-center justify-end gap-2">
            <div className="relative hidden w-72 md:block">
              <label htmlFor="global-search" className="sr-only">Search</label>
              <Search className="pointer-events-none absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-muted-foreground" />
              <input
                id="global-search"
                placeholder="Search UAVs, missions, certificates…"
                className="h-8 w-full rounded-md border border-border bg-surface pl-8 pr-3 text-[13px] outline-none placeholder:text-muted-foreground focus:border-primary focus:ring-2 focus:ring-ring"
              />
            </div>
            <NotificationCenter />
            <button
              type="button"
              aria-label="Help"
              className="flex h-8 w-8 items-center justify-center rounded-md border border-border bg-background hover:bg-surface-2 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
            >
              <HelpCircle className="h-4 w-4 text-muted-foreground" />
            </button>
            <button
              type="button"
              aria-label="Settings"
              className="flex h-8 w-8 items-center justify-center rounded-md border border-border bg-background hover:bg-surface-2 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
            >
              <Settings className="h-4 w-4 text-muted-foreground" />
            </button>
            
            {/* Logged in Profile Info */}
            <div className="ml-2 flex items-center gap-2 rounded-md border border-border bg-background px-2 py-1">
              <div className="flex h-6 w-6 items-center justify-center rounded-full bg-primary/10 text-[10px] font-semibold text-primary font-mono" aria-hidden="true">
                {userInitials}
              </div>
              <div className="hidden text-[11.5px] leading-tight md:block">
                <div className="font-semibold capitalize text-foreground">{authState.username}</div>
                <div className="text-tabular text-[9.5px] font-semibold text-primary uppercase">{authState.role}</div>
              </div>
              <button
                type="button"
                onClick={() => logout()}
                title="Invalidate session and Logout"
                className="ml-1 rounded-md p-1 hover:bg-surface-2 text-muted-foreground hover:text-foreground"
              >
                <LogOut className="h-3.5 w-3.5" />
              </button>
            </div>
          </div>
        </div>
        <EventTicker />
      </header>

      <div className="flex">
        {/* Desktop side nav */}
        <aside className="sticky top-[calc(3.5rem+1.75rem)] hidden h-[calc(100dvh-3.5rem-1.75rem)] w-60 shrink-0 border-r border-border bg-background lg:block">
          <SideNav pathname={pathname} />
        </aside>

        {/* Mobile drawer */}
        {mobileOpen && (
          <div className="fixed inset-0 z-50 lg:hidden" role="dialog" aria-modal="true" aria-label="Navigation">
            <div
              className="absolute inset-0 bg-overlay animate-fade-in-scale"
              onClick={() => setMobileOpen(false)}
            />
            <div className="animate-fade-in-up absolute inset-y-0 left-0 w-72 border-r border-border bg-background shadow-lg">
              <div className="flex items-center justify-between border-b border-border px-4 py-3">
                <span className="text-[13px] font-semibold">Navigation</span>
                <button
                  type="button"
                  onClick={() => setMobileOpen(false)}
                  aria-label="Close navigation"
                  className="flex h-8 w-8 items-center justify-center rounded-md border border-border hover:bg-surface-2 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
                >
                  <X className="h-4 w-4" />
                </button>
              </div>
              <SideNav pathname={pathname} onNavigate={() => setMobileOpen(false)} />
            </div>
          </div>
        )}

        {/* Content */}
        <main id="main" className="min-w-0 flex-1">
          <div className="border-b border-border bg-background">
            <div className="px-4 pb-5 pt-6 md:px-8">
              {breadcrumbs && breadcrumbs.length > 0 && (
                <nav className="mb-2 flex flex-wrap items-center gap-1.5 text-[12px] text-muted-foreground" aria-label="Breadcrumb">
                  {breadcrumbs.map((b, i) => (
                    <span key={i} className="flex items-center gap-1.5">
                      {b.to ? (
                        <Link to={b.to} className="hover:text-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring">
                          {b.label}
                        </Link>
                      ) : (
                        <span aria-current="page">{b.label}</span>
                      )}
                      {i < breadcrumbs.length - 1 && <ChevronRight className="h-3 w-3" aria-hidden="true" />}
                    </span>
                  ))}
                </nav>
              )}
              <div className="flex flex-wrap items-end justify-between gap-4">
                <div>
                  {eyebrow && <div className="text-overline mb-1.5">{eyebrow}</div>}
                  <h1 className="text-[22px] font-semibold tracking-tight text-foreground">{title}</h1>
                </div>
                {actions && <div className="flex flex-wrap items-center gap-2">{actions}</div>}
              </div>
            </div>
          </div>

          <div className="animate-fade-in-up px-4 py-6 md:px-8">{children}</div>
        </main>
      </div>
    </div>
  );
}
