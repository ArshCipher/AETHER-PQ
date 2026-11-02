// Shared "live-feel" primitives: LiveClock, LiveNumber, LiveDot, PacketFlow,
// Skeleton, EmptyState, and a NotificationCenter popover.
import { useEffect, useRef, useState } from "react";
import { Bell, Check, Inbox } from "lucide-react";
import { useCountUp, useLiveClock, useHydrated } from "@/hooks/use-live";
import { type ActivityEvent } from "@/lib/types";
import { useWebSocketContext } from "@/components/websocket-provider";
import { cn } from "@/lib/utils";

/** Ticking UTC clock. SSR-safe: renders a stable placeholder pre-hydration. */
export function LiveClock({ className }: { className?: string }) {
  const t = useLiveClock();
  return (
    <span
      className={cn("text-tabular", className)}
      aria-label="Current UTC time"
      suppressHydrationWarning
    >
      {t}
    </span>
  );
}

/** Smoothly animated numeric readout with tabular alignment. */
export function LiveNumber({
  value, decimals = 0, prefix, suffix, className,
}: { value: number; decimals?: number; prefix?: string; suffix?: string; className?: string }) {
  const hydrated = useHydrated();
  const v = useCountUp(hydrated ? value : value);
  return (
    <span className={cn("text-tabular tabular-nums", className)}>
      {prefix}
      {v.toLocaleString(undefined, { minimumFractionDigits: decimals, maximumFractionDigits: decimals })}
      {suffix}
    </span>
  );
}

/** Softly pulsing status dot. */
export function LiveDot({ tone = "success", pulse = true, className }: {
  tone?: "success" | "warning" | "critical" | "neutral" | "info";
  pulse?: boolean;
  className?: string;
}) {
  const color =
    tone === "success" ? "var(--color-success)"
    : tone === "warning" ? "var(--color-warning)"
    : tone === "critical" ? "var(--color-critical)"
    : tone === "info" ? "var(--color-primary)"
    : "var(--color-muted-foreground)";
  return (
    <span
      className={cn("relative inline-flex h-2 w-2 items-center justify-center", className)}
      aria-hidden="true"
    >
      <span
        className={cn("absolute inline-flex h-full w-full rounded-full opacity-60", pulse && "animate-live-ping")}
        style={{ background: color }}
      />
      <span
        className="relative inline-flex h-2 w-2 rounded-full"
        style={{ background: color }}
      />
    </span>
  );
}

/** Animated packet-flow line — evokes secure traffic movement. Purely decorative. */
export function PacketFlow({ tone = "primary", className }: { tone?: "primary" | "success" | "warning"; className?: string }) {
  const color =
    tone === "success" ? "var(--color-success)"
    : tone === "warning" ? "var(--color-warning)"
    : "var(--color-primary)";
  return (
    <div
      role="presentation"
      className={cn("relative h-[2px] w-full overflow-hidden rounded-full bg-surface-2", className)}
    >
      <span
        className="absolute inset-y-0 -left-1/3 w-1/3 animate-packet-flow rounded-full"
        style={{ background: `linear-gradient(90deg, transparent, ${color}, transparent)` }}
      />
    </div>
  );
}

/** Rectangular skeleton — for loading states before data resolves. */
export function Skeleton({ className }: { className?: string }) {
  return <div className={cn("animate-skeleton rounded-md bg-surface-2", className)} aria-hidden="true" />;
}

/** Standard empty state block. */
export function EmptyState({
  title, description, icon: Icon = Inbox, action,
}: {
  title: string;
  description?: string;
  icon?: React.ComponentType<{ className?: string; strokeWidth?: number }>;
  action?: React.ReactNode;
}) {
  return (
    <div className="flex flex-col items-center justify-center gap-2 rounded-lg border border-dashed border-border bg-surface/60 px-6 py-10 text-center">
      <div className="flex h-9 w-9 items-center justify-center rounded-full bg-surface-2 text-muted-foreground">
        <Icon className="h-4 w-4" strokeWidth={2} />
      </div>
      <div className="text-[13.5px] font-medium text-foreground">{title}</div>
      {description && <div className="max-w-sm text-[12.5px] text-muted-foreground">{description}</div>}
      {action && <div className="mt-2">{action}</div>}
    </div>
  );
}

/** Compact notification popover triggered from the AppShell bell. */
export function NotificationCenter() {
  const [open, setOpen] = useState(false);
  const ref = useRef<HTMLDivElement | null>(null);
  const [seen, setSeen] = useState<Set<string>>(new Set());

  useEffect(() => {
    if (!open) return;
    const onDown = (e: MouseEvent) => {
      if (ref.current && !ref.current.contains(e.target as Node)) setOpen(false);
    };
    const onKey = (e: KeyboardEvent) => { if (e.key === "Escape") setOpen(false); };
    document.addEventListener("mousedown", onDown);
    document.addEventListener("keydown", onKey);
    return () => {
      document.removeEventListener("mousedown", onDown);
      document.removeEventListener("keydown", onKey);
    };
  }, [open]);

  const { data } = useWebSocketContext();
  const items = (data?.recentActivity || []).slice(0, 8);
  const unread = items.filter((i: any) => !seen.has(i.ts)).length;

  return (
    <div className="relative" ref={ref}>
      <button
        type="button"
        aria-label={`Notifications (${unread} unread)`}
        aria-expanded={open}
        aria-haspopup="dialog"
        onClick={() => setOpen((o) => !o)}
        className="relative flex h-8 w-8 items-center justify-center rounded-md border border-border bg-background transition-colors hover:bg-surface-2 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
      >
        <Bell className="h-4 w-4 text-muted-foreground" />
        {unread > 0 && (
          <span
            className="absolute -right-0.5 -top-0.5 flex h-4 min-w-4 items-center justify-center rounded-full bg-critical px-1 text-[9px] font-semibold text-critical-foreground"
            aria-hidden="true"
          >
            {unread}
          </span>
        )}
      </button>
      {open && (
        <div
          role="dialog"
          aria-label="Notifications"
          className="animate-fade-in-scale absolute right-0 z-50 mt-2 w-[360px] origin-top-right overflow-hidden rounded-lg border border-border bg-card shadow-lg"
        >
          <div className="flex items-center justify-between border-b border-border px-4 py-2.5">
            <div>
              <div className="text-[13px] font-semibold text-foreground">Notifications</div>
              <div className="text-tabular text-[11px] text-muted-foreground">{unread} unread · {items.length} recent</div>
            </div>
            <button
              type="button"
              onClick={() => setSeen(new Set(items.map((i) => i.ts)))}
              className="inline-flex items-center gap-1 rounded-md px-1.5 py-1 text-[11.5px] text-primary hover:bg-primary-muted focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
            >
              <Check className="h-3 w-3" /> Mark all read
            </button>
          </div>
          <ul className="max-h-[360px] overflow-y-auto">
            {items.map((e) => <NotifRow key={e.ts + e.message} e={e} unread={!seen.has(e.ts)} />)}
          </ul>
          <div className="border-t border-border bg-surface px-4 py-2 text-right">
            <a href="/logs" className="text-[12px] text-primary hover:underline">Open audit log →</a>
          </div>
        </div>
      )}
    </div>
  );
}

function NotifRow({ e, unread }: { e: ActivityEvent; unread: boolean }) {
  const tone =
    e.severity === "critical" ? "critical" :
    e.severity === "warning" ? "warning" :
    e.severity === "success" ? "success" : "info";
  return (
    <li className="flex items-start gap-3 border-b border-border px-4 py-2.5 last:border-b-0 hover:bg-surface">
      <div className="mt-1"><LiveDot tone={tone} pulse={e.severity === "critical"} /></div>
      <div className="min-w-0 flex-1">
        <div className="flex items-center gap-2">
          <span className="text-tabular text-[10px] uppercase tracking-wider text-muted-foreground">{e.actor}</span>
          <span className="text-tabular text-[10px] text-muted-foreground">{e.ts}</span>
          {unread && <span className="ml-auto rounded-sm bg-primary-muted px-1 text-[9px] font-semibold uppercase text-primary">New</span>}
        </div>
        <div className="mt-0.5 text-[12.5px] text-foreground">{e.message}</div>
      </div>
    </li>
  );
}
