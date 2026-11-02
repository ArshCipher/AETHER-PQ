import { createFileRoute } from "@tanstack/react-router";
import {
  Activity,
  AlertTriangle,
  ArrowUpRight,
  CheckCircle2,
  ChevronRight,
  CircleDot,
  Cpu,
  Fingerprint,
  Key,
  Lock,
  Network,
  Plane,
  Radio,
  Radar,
  Satellite,
  ShieldCheck,
  Signal,
  Terminal,
  Zap,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { Progress } from "@/components/ui/progress";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Switch } from "@/components/ui/switch";
import { Skeleton } from "@/components/ui/skeleton";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import {
  Tooltip,
  TooltipContent,
  TooltipProvider,
  TooltipTrigger,
} from "@/components/ui/tooltip";

export const Route = createFileRoute("/system")({
  component: DesignSystem,
});

/* ------------------------------------------------------------------ */
/* Primitives                                                          */
/* ------------------------------------------------------------------ */

function Section({
  id,
  eyebrow,
  title,
  desc,
  children,
}: {
  id: string;
  eyebrow: string;
  title: string;
  desc?: string;
  children: React.ReactNode;
}) {
  return (
    <section id={id} className="scroll-mt-24 border-t border-border/70 py-14">
      <header className="mb-8 flex items-end justify-between gap-8">
        <div>
          <div className="text-overline text-accent">{eyebrow}</div>
          <h2 className="mt-2 text-2xl font-semibold tracking-tight text-foreground">
            {title}
          </h2>
          {desc && (
            <p className="mt-2 max-w-2xl text-sm text-muted-foreground">{desc}</p>
          )}
        </div>
        <div className="hidden text-tabular text-[11px] text-muted-foreground md:block">
          {id.toUpperCase()} · REV 01
        </div>
      </header>
      {children}
    </section>
  );
}

function Panel({
  children,
  className = "",
  hud = false,
}: {
  children: React.ReactNode;
  className?: string;
  hud?: boolean;
}) {
  return (
    <div
      className={`panel ${hud ? "hud-corner" : ""} p-5 ${className}`.trim()}
    >
      {children}
    </div>
  );
}

function TokenChip({
  name,
  value,
  swatch,
}: {
  name: string;
  value: string;
  swatch: string;
}) {
  return (
    <div className="panel flex items-center gap-3 p-3">
      <div
        className="h-10 w-10 shrink-0 rounded-sm border border-border-strong"
        style={{ background: swatch }}
      />
      <div className="min-w-0 flex-1">
        <div className="truncate text-xs font-medium text-foreground">{name}</div>
        <div className="truncate text-tabular text-[10.5px] text-muted-foreground">
          {value}
        </div>
      </div>
    </div>
  );
}

function StatusDot({
  tone,
  pulse = false,
}: {
  tone: "success" | "warning" | "critical" | "info" | "neutral";
  pulse?: boolean;
}) {
  const map = {
    success: "text-success",
    warning: "text-warning",
    critical: "text-critical",
    info: "text-info",
    neutral: "text-neutral",
  } as const;
  return (
    <span className={`relative inline-flex ${map[tone]}`}>
      <span
        className={`inline-block h-2 w-2 rounded-full bg-current ${
          pulse ? "pulse-dot" : ""
        }`}
      />
    </span>
  );
}

function Kbd({ children }: { children: React.ReactNode }) {
  return (
    <kbd className="inline-flex h-5 min-w-5 items-center justify-center rounded-sm border border-border-strong bg-surface-2 px-1.5 text-[10.5px] font-medium text-muted-foreground">
      {children}
    </kbd>
  );
}

/* ------------------------------------------------------------------ */
/* Page                                                                */
/* ------------------------------------------------------------------ */

function DesignSystem() {
  return (
    <TooltipProvider delayDuration={100}>
      <div className="min-h-screen bg-background text-foreground">
        <TopBar />
        <div className="mx-auto grid max-w-[1440px] grid-cols-1 gap-0 px-6 lg:grid-cols-[220px_1fr]">
          <SideNav />
          <main className="min-w-0 pb-24">
            <Hero />
            <Foundations />
            <Typography />
            <ColorSystem />
            <Elevation />
            <Buttons />
            <FormsSection />
            <StatusSection />
            <CardsSection />
            <MissionComponents />
            <DataDisplay />
            <FeedbackStates />
            <Architecture />
            <Footer />
          </main>
        </div>
      </div>
    </TooltipProvider>
  );
}

/* ------------------------------------------------------------------ */
/* Chrome                                                              */
/* ------------------------------------------------------------------ */

function TopBar() {
  return (
    <div className="sticky top-0 z-40 border-b border-border/70 bg-background/85 backdrop-blur-md">
      <div className="mx-auto flex h-14 max-w-[1440px] items-center justify-between gap-6 px-6">
        <div className="flex items-center gap-3">
          <div className="relative flex h-8 w-8 items-center justify-center rounded-sm bg-gradient-to-br from-accent to-primary">
            <ShieldCheck className="h-4 w-4 text-background" strokeWidth={2.5} />
          </div>
          <div className="leading-tight">
            <div className="text-[13px] font-semibold tracking-tight">
              AETHER<span className="text-accent">·</span>PQ
            </div>
            <div className="text-tabular text-[10px] text-muted-foreground">
              MISSION CONTROL / DESIGN SYSTEM v1.0
            </div>
          </div>
        </div>
        <nav className="hidden items-center gap-1 text-[13px] text-muted-foreground md:flex">
          {["Overview", "Fleet", "Cryptography", "Topology", "Telemetry", "Simulation"].map(
            (l, i) => (
              <a
                key={l}
                className={`rounded-sm px-3 py-1.5 hover:bg-surface-2 hover:text-foreground ${
                  i === 0 ? "bg-surface-2 text-foreground" : ""
                }`}
                href="#"
              >
                {l}
              </a>
            ),
          )}
        </nav>
        <div className="flex items-center gap-3">
          <div className="hidden items-center gap-2 rounded-sm border border-border bg-surface px-2.5 py-1.5 md:flex">
            <StatusDot tone="success" pulse />
            <span className="text-tabular text-[11px] text-muted-foreground">
              LINK · 128 ms · PQ-HYBRID
            </span>
          </div>
          <Kbd>⌘</Kbd>
          <Kbd>K</Kbd>
        </div>
      </div>
    </div>
  );
}

function SideNav() {
  const groups: { label: string; items: { href: string; name: string }[] }[] = [
    {
      label: "Foundations",
      items: [
        { href: "#foundations", name: "Principles" },
        { href: "#typography", name: "Typography" },
        { href: "#color", name: "Color" },
        { href: "#elevation", name: "Elevation & Grid" },
      ],
    },
    {
      label: "Components",
      items: [
        { href: "#buttons", name: "Buttons" },
        { href: "#forms", name: "Forms" },
        { href: "#status", name: "Status & Badges" },
        { href: "#cards", name: "Cards & KPI" },
        { href: "#mission", name: "Mission" },
        { href: "#data", name: "Data & Tables" },
        { href: "#feedback", name: "Feedback" },
      ],
    },
    {
      label: "Architecture",
      items: [{ href: "#architecture", name: "Information Model" }],
    },
  ];
  return (
    <aside className="sticky top-14 hidden h-[calc(100vh-3.5rem)] overflow-y-auto border-r border-border/70 py-8 pr-4 text-[13px] lg:block">
      <nav className="space-y-6">
        {groups.map((g) => (
          <div key={g.label}>
            <div className="text-overline mb-2 px-2">{g.label}</div>
            <ul className="space-y-0.5">
              {g.items.map((it) => (
                <li key={it.href}>
                  <a
                    className="group flex items-center justify-between rounded-sm px-2 py-1.5 text-muted-foreground hover:bg-surface-2 hover:text-foreground"
                    href={it.href}
                  >
                    <span>{it.name}</span>
                    <ChevronRight className="h-3.5 w-3.5 opacity-0 transition-opacity group-hover:opacity-100" />
                  </a>
                </li>
              ))}
            </ul>
          </div>
        ))}
      </nav>
    </aside>
  );
}

/* ------------------------------------------------------------------ */
/* Sections                                                            */
/* ------------------------------------------------------------------ */

function Hero() {
  return (
    <section className="relative overflow-hidden border-b border-border/70">
      <div className="grid-bg scanline absolute inset-0 opacity-60" />
      <div className="relative py-16">
        <div className="flex items-center gap-2">
          <Badge
            variant="outline"
            className="border-accent/40 bg-accent/10 text-accent"
          >
            <Fingerprint className="mr-1 h-3 w-3" />
            CLASSIFIED · INTERNAL
          </Badge>
          <span className="text-overline">Design System · v1.0</span>
        </div>
        <h1 className="text-display mt-6 max-w-3xl text-foreground">
          The visual language of a{" "}
          <span className="text-accent">post-quantum</span> mission control
          platform.
        </h1>
        <p className="mt-5 max-w-2xl text-[15px] leading-relaxed text-muted-foreground">
          AETHER-PQ is a research-grade command surface for UAV fleets operating
          under hybrid classical and post-quantum cryptography. This system codifies
          every token, component and interaction pattern used across the platform —
          from the certificate authority to the ground control station to the ns-3
          simulation harness.
        </p>
        <div className="mt-8 flex flex-wrap items-center gap-3">
          <Button size="lg" className="gap-2">
            Open Mission Console
            <ArrowUpRight className="h-4 w-4" />
          </Button>
          <Button size="lg" variant="outline" className="gap-2">
            <Terminal className="h-4 w-4" />
            Component Reference
          </Button>
          <div className="ml-2 flex items-center gap-4 text-tabular text-[11px] text-muted-foreground">
            <span>
              BUILD <span className="text-foreground">2026.07.08-a3f2</span>
            </span>
            <span className="h-3 w-px bg-border" />
            <span>
              CIPHER SUITE <span className="text-accent">X25519+ML-KEM-768</span>
            </span>
          </div>
        </div>

        {/* Vital strip */}
        <div className="mt-12 grid grid-cols-2 gap-px overflow-hidden rounded-md border border-border bg-border md:grid-cols-4">
          {[
            { k: "FLEET ONLINE", v: "24 / 26", tone: "success" as const, sub: "2 in maintenance" },
            { k: "GROUP KEY EPOCH", v: "e-1442", tone: "info" as const, sub: "TreeKEM rotated 04m ago" },
            { k: "POLICY LEVEL", v: "L3 · HYBRID", tone: "warning" as const, sub: "ACPE elevated" },
            { k: "CRITICAL ALERTS", v: "0", tone: "neutral" as const, sub: "24h window" },
          ].map((s) => (
            <div key={s.k} className="bg-panel px-5 py-4">
              <div className="flex items-center justify-between">
                <div className="text-overline">{s.k}</div>
                <StatusDot tone={s.tone} />
              </div>
              <div className="mt-2 text-tabular text-[22px] font-semibold tracking-tight text-foreground">
                {s.v}
              </div>
              <div className="mt-1 text-[11.5px] text-muted-foreground">{s.sub}</div>
            </div>
          ))}
        </div>
      </div>
    </section>
  );
}

function Foundations() {
  const principles = [
    {
      icon: ShieldCheck,
      title: "Truth over decoration",
      body: "Every pixel earns its place. Chrome exists to make signal legible — never to entertain.",
    },
    {
      icon: Radar,
      title: "State is the interface",
      body: "The operator reads system state in one glance: identity, integrity, epoch, link, policy.",
    },
    {
      icon: Zap,
      title: "Latency-honest",
      body: "The UI never lies about time. Stale data is labeled; realtime data is tabular and monospaced.",
    },
    {
      icon: Lock,
      title: "Cryptography is first-class",
      body: "Suite, epoch, key material and policy level are surfaced as ambient context, not buried.",
    },
  ];
  return (
    <Section
      id="foundations"
      eyebrow="§01 · Foundations"
      title="Design principles"
      desc="Four commitments that shape every screen in the platform."
    >
      <div className="grid grid-cols-1 gap-4 md:grid-cols-2">
        {principles.map((p) => (
          <Panel key={p.title}>
            <div className="flex items-start gap-4">
              <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-sm border border-border-strong bg-surface-2 text-accent">
                <p.icon className="h-5 w-5" />
              </div>
              <div>
                <div className="text-[14px] font-semibold text-foreground">
                  {p.title}
                </div>
                <p className="mt-1.5 text-[13px] leading-relaxed text-muted-foreground">
                  {p.body}
                </p>
              </div>
            </div>
          </Panel>
        ))}
      </div>
    </Section>
  );
}

function Typography() {
  const rows = [
    { name: "Display", cls: "text-display", sample: "Mission Control", note: "Inter · 48/1.05 · -0.02em" },
    { name: "H1", cls: "text-3xl font-semibold tracking-tight", sample: "Fleet Overview", note: "Inter · 30/1.15" },
    { name: "H2", cls: "text-2xl font-semibold tracking-tight", sample: "Cryptographic Policy", note: "Inter · 24/1.2" },
    { name: "H3", cls: "text-lg font-semibold", sample: "Group Key Rotation", note: "Inter · 18/1.35" },
    { name: "Title", cls: "text-[15px] font-semibold", sample: "UAV-014 · Falcon", note: "Inter · 15/1.4" },
    { name: "Body", cls: "text-sm", sample: "Handshake completed with hybrid suite X25519+ML-KEM-768 at 04:12:07Z.", note: "Inter · 14/1.55" },
    { name: "Caption", cls: "text-xs text-muted-foreground", sample: "Last telemetry frame 218 ms ago", note: "Inter · 12/1.5" },
    { name: "Overline", cls: "text-overline", sample: "Adaptive Cryptographic Policy Engine", note: "JetBrains Mono · 11 · 0.14em" },
    { name: "Tabular", cls: "text-tabular text-sm", sample: "128.44 ms · 99.982% · 04:12:07.221Z", note: "JetBrains Mono · tnum" },
    { name: "Code", cls: "font-mono text-xs bg-surface-2 px-2 py-1 rounded-sm border border-border", sample: "kem::mlkem768::encaps(pk)", note: "JetBrains Mono · 12" },
  ];
  return (
    <Section
      id="typography"
      eyebrow="§02 · Typography"
      title="Hierarchy for dense operator surfaces"
      desc="Inter for prose and headings; JetBrains Mono for identifiers, telemetry, coordinates, timestamps and code."
    >
      <Panel className="overflow-hidden !p-0">
        <div className="divide-y divide-border">
          {rows.map((r) => (
            <div
              key={r.name}
              className="grid grid-cols-[140px_1fr_260px] items-center gap-6 px-5 py-4"
            >
              <div className="text-overline">{r.name}</div>
              <div className={r.cls}>{r.sample}</div>
              <div className="text-tabular text-[11px] text-muted-foreground">
                {r.note}
              </div>
            </div>
          ))}
        </div>
      </Panel>
    </Section>
  );
}

function ColorSystem() {
  return (
    <Section
      id="color"
      eyebrow="§03 · Color"
      title="A restrained enterprise palette"
      desc="Color is reserved for state and hierarchy. No rainbows, no gradients-as-brand."
    >
      <div className="space-y-6">
        <div>
          <div className="text-overline mb-3">Surfaces</div>
          <div className="grid grid-cols-2 gap-3 md:grid-cols-4 lg:grid-cols-6">
            <TokenChip name="background" value="oklch(.16 .02 250)" swatch="var(--background)" />
            <TokenChip name="surface" value="oklch(.19 .022 250)" swatch="var(--surface)" />
            <TokenChip name="surface-2" value="oklch(.22 .024 250)" swatch="var(--surface-2)" />
            <TokenChip name="surface-3" value="oklch(.26 .026 250)" swatch="var(--surface-3)" />
            <TokenChip name="panel" value="gradient" swatch="var(--gradient-panel)" />
            <TokenChip name="elevated" value="oklch(.24 .025 250)" swatch="var(--elevated)" />
          </div>
        </div>
        <div>
          <div className="text-overline mb-3">Brand · Interactive</div>
          <div className="grid grid-cols-2 gap-3 md:grid-cols-4 lg:grid-cols-6">
            <TokenChip name="primary · deep navy" value="oklch(.62 .14 245)" swatch="var(--primary)" />
            <TokenChip name="secondary · slate" value="oklch(.30 .04 250)" swatch="var(--secondary)" />
            <TokenChip name="accent · electric cyan" value="oklch(.78 .14 210)" swatch="var(--accent)" />
            <TokenChip name="accent glow" value="oklch(.82 .16 205)" swatch="var(--accent-glow)" />
            <TokenChip name="ring" value="accent / .6" swatch="var(--ring)" />
            <TokenChip name="gradient · accent" value="cyan → navy" swatch="var(--gradient-accent)" />
          </div>
        </div>
        <div>
          <div className="text-overline mb-3">Status semantics</div>
          <div className="grid grid-cols-2 gap-3 md:grid-cols-4 lg:grid-cols-6">
            <TokenChip name="success · nominal" value="oklch(.74 .16 155)" swatch="var(--success)" />
            <TokenChip name="warning · degraded" value="oklch(.80 .14 78)" swatch="var(--warning)" />
            <TokenChip name="critical · fault" value="oklch(.66 .22 25)" swatch="var(--critical)" />
            <TokenChip name="info · advisory" value="oklch(.72 .13 230)" swatch="var(--info)" />
            <TokenChip name="neutral · idle" value="oklch(.56 .02 250)" swatch="var(--neutral)" />
            <TokenChip name="muted-foreground" value="oklch(.70 .02 250)" swatch="var(--muted-foreground)" />
          </div>
        </div>
        <div>
          <div className="text-overline mb-3">Data visualization · categorical</div>
          <div className="grid grid-cols-3 gap-3 md:grid-cols-6">
            {[1, 2, 3, 4, 5, 6].map((n) => (
              <TokenChip
                key={n}
                name={`chart-${n}`}
                value={`var(--chart-${n})`}
                swatch={`var(--chart-${n})`}
              />
            ))}
          </div>
        </div>
      </div>
    </Section>
  );
}

function Elevation() {
  const shadows = [
    { name: "shadow-xs", var: "--shadow-xs", desc: "Divider · inline" },
    { name: "shadow-sm", var: "--shadow-sm", desc: "Panels · cards" },
    { name: "shadow-md", var: "--shadow-md", desc: "Popovers · menus" },
    { name: "shadow-lg", var: "--shadow-lg", desc: "Dialogs · drawers" },
    { name: "shadow-xl", var: "--shadow-xl", desc: "Command palette" },
    { name: "shadow-glow", var: "--shadow-glow", desc: "Focus · alert" },
  ];
  return (
    <Section
      id="elevation"
      eyebrow="§04 · Elevation · Grid · Radius · Spacing"
      title="Structure"
      desc="A 4/8 spacing scale, restrained corner radii, and layered shadows tuned for a dark ops surface."
    >
      <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">
        <Panel>
          <div className="text-overline mb-4">Elevation</div>
          <div className="space-y-3">
            {shadows.map((s) => (
              <div key={s.name} className="flex items-center gap-4">
                <div
                  className="h-12 w-20 shrink-0 rounded-sm border border-border bg-elevated"
                  style={{ boxShadow: `var(${s.var})` }}
                />
                <div className="min-w-0">
                  <div className="text-tabular text-[12px] text-foreground">
                    {s.name}
                  </div>
                  <div className="text-[11.5px] text-muted-foreground">{s.desc}</div>
                </div>
              </div>
            ))}
          </div>
        </Panel>
        <Panel>
          <div className="text-overline mb-4">Radius</div>
          <div className="space-y-3">
            {[
              ["radius-xs", "2px", "Chips · pills · inline tags"],
              ["radius-sm", "4px", "Inputs · buttons · badges"],
              ["radius-md", "6px", "Panels · cards · popovers"],
              ["radius-lg", "8px", "Dialogs · sheets"],
              ["radius-xl", "12px", "Marketing surfaces"],
            ].map(([name, val, note]) => (
              <div key={name} className="flex items-center gap-4">
                <div
                  className="h-12 w-20 shrink-0 border border-border-strong bg-surface-2"
                  style={{ borderRadius: `var(--${name})` }}
                />
                <div className="min-w-0">
                  <div className="text-tabular text-[12px] text-foreground">
                    {name} · {val}
                  </div>
                  <div className="text-[11.5px] text-muted-foreground">{note}</div>
                </div>
              </div>
            ))}
          </div>
        </Panel>
        <Panel>
          <div className="text-overline mb-4">Spacing · 4pt base</div>
          <div className="space-y-2">
            {[4, 8, 12, 16, 24, 32, 48, 64].map((n) => (
              <div key={n} className="flex items-center gap-3">
                <div className="text-tabular w-10 text-[11.5px] text-muted-foreground">
                  {n}px
                </div>
                <div
                  className="h-2 rounded-xs bg-accent/70"
                  style={{ width: n * 3 }}
                />
              </div>
            ))}
            <div className="mt-6 grid-bg h-24 rounded-sm border border-border-subtle" />
            <div className="text-overline mt-2">12-column grid · 32px gutter</div>
          </div>
        </Panel>
      </div>
    </Section>
  );
}

function Buttons() {
  return (
    <Section
      id="buttons"
      eyebrow="§05 · Buttons"
      title="Action affordances"
      desc="Actions are ranked: primary for commit, outline for navigation, ghost for chrome, destructive for irreversible."
    >
      <Panel>
        <div className="space-y-6">
          <div>
            <div className="text-overline mb-3">Hierarchy</div>
            <div className="flex flex-wrap items-center gap-3">
              <Button>Commit rotation</Button>
              <Button variant="secondary">Stage change</Button>
              <Button variant="outline">Inspect</Button>
              <Button variant="ghost">Cancel</Button>
              <Button variant="destructive">Revoke certificate</Button>
              <Button variant="link">View audit log</Button>
            </div>
          </div>
          <div>
            <div className="text-overline mb-3">Size</div>
            <div className="flex flex-wrap items-center gap-3">
              <Button size="sm">Small</Button>
              <Button>Default</Button>
              <Button size="lg">Large</Button>
              <Button size="icon" aria-label="Terminal">
                <Terminal className="h-4 w-4" />
              </Button>
              <Button className="gap-2">
                <Key className="h-4 w-4" /> Rotate group key
              </Button>
              <Button variant="outline" className="gap-2">
                Inspect certificate <ArrowUpRight className="h-4 w-4" />
              </Button>
            </div>
          </div>
          <div>
            <div className="text-overline mb-3">State</div>
            <div className="flex flex-wrap items-center gap-3">
              <Button disabled>Disabled</Button>
              <Button className="gap-2">
                <span className="h-3 w-3 animate-spin rounded-full border-2 border-primary-foreground/40 border-t-primary-foreground" />
                Handshaking…
              </Button>
              <Button
                variant="outline"
                className="gap-2 border-success/50 text-success hover:bg-success/10 hover:text-success"
              >
                <CheckCircle2 className="h-4 w-4" /> Verified
              </Button>
              <Button
                variant="outline"
                className="gap-2 border-critical/50 text-critical hover:bg-critical/10 hover:text-critical"
              >
                <AlertTriangle className="h-4 w-4" /> Attention
              </Button>
            </div>
          </div>
        </div>
      </Panel>
    </Section>
  );
}

function FormsSection() {
  return (
    <Section
      id="forms"
      eyebrow="§06 · Forms"
      title="Inputs, selects, switches"
      desc="Field density is tight; labels are overline; help text is caption. Errors are inline, never modal."
    >
      <div className="grid grid-cols-1 gap-4 md:grid-cols-2">
        <Panel>
          <div className="space-y-5">
            <div>
              <label className="text-overline mb-1.5 block">Callsign</label>
              <Input placeholder="FALCON-014" defaultValue="FALCON-014" />
              <p className="mt-1.5 text-[11.5px] text-muted-foreground">
                Alphanumeric, 3–24 characters. Broadcast on MAVLink HEARTBEAT.
              </p>
            </div>
            <div>
              <label className="text-overline mb-1.5 block">
                Cipher suite
              </label>
              <Select defaultValue="hybrid">
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="classical">
                    Classical · X25519 + AES-256-GCM
                  </SelectItem>
                  <SelectItem value="hybrid">
                    Hybrid · X25519 + ML-KEM-768
                  </SelectItem>
                  <SelectItem value="pq">
                    Post-quantum only · ML-KEM-1024 + ML-DSA-87
                  </SelectItem>
                </SelectContent>
              </Select>
            </div>
            <div className="flex items-center justify-between border-t border-border pt-4">
              <div>
                <div className="text-[13px] font-medium">
                  Adaptive policy engine
                </div>
                <div className="text-[11.5px] text-muted-foreground">
                  Escalate suite when link entropy drops.
                </div>
              </div>
              <Switch defaultChecked />
            </div>
            <div className="flex items-center justify-between">
              <div>
                <div className="text-[13px] font-medium">
                  ns-3 simulation mirror
                </div>
                <div className="text-[11.5px] text-muted-foreground">
                  Replicate live topology into sim.
                </div>
              </div>
              <Switch />
            </div>
          </div>
        </Panel>
        <Panel>
          <div className="space-y-5">
            <div>
              <label className="text-overline mb-1.5 block">
                Certificate CN — error
              </label>
              <Input
                defaultValue="uav.14@fleet.local"
                className="border-critical/60 focus-visible:ring-critical/40"
              />
              <p className="mt-1.5 flex items-center gap-1.5 text-[11.5px] text-critical">
                <AlertTriangle className="h-3 w-3" />
                Certificate expired 2 days ago. Reissue via CA.
              </p>
            </div>
            <div>
              <label className="text-overline mb-1.5 block">
                Group epoch note
              </label>
              <textarea
                className="min-h-24 w-full rounded-sm border border-input bg-surface px-3 py-2 text-sm placeholder:text-muted-foreground focus-visible:outline-hidden focus-visible:ring-2 focus-visible:ring-ring"
                placeholder="Scheduled TreeKEM rotation at 04:00Z. Reason: policy L3 activation."
                defaultValue="Scheduled TreeKEM rotation at 04:00Z. Reason: policy L3 activation."
              />
            </div>
            <div>
              <label className="text-overline mb-1.5 block">
                Handshake progress
              </label>
              <Progress value={64} className="h-1.5" />
              <div className="mt-1.5 flex justify-between text-tabular text-[11px] text-muted-foreground">
                <span>KEM encapsulation · 64%</span>
                <span>ETA 118 ms</span>
              </div>
            </div>
          </div>
        </Panel>
      </div>
    </Section>
  );
}

function StatusSection() {
  const badges: {
    label: string;
    tone: "success" | "warning" | "critical" | "info" | "neutral";
    pulse?: boolean;
  }[] = [
    { label: "NOMINAL", tone: "success" },
    { label: "DEGRADED · LINK", tone: "warning" },
    { label: "FAULT · CRYPTO", tone: "critical", pulse: true },
    { label: "ADVISORY", tone: "info" },
    { label: "STANDBY", tone: "neutral" },
  ];
  return (
    <Section
      id="status"
      eyebrow="§07 · Status · Badges · Chips"
      title="A single vocabulary of state"
      desc="Five tones cover every state in the platform: nominal, degraded, fault, advisory, standby."
    >
      <div className="grid grid-cols-1 gap-4 md:grid-cols-2">
        <Panel>
          <div className="text-overline mb-4">Status pills</div>
          <div className="flex flex-wrap gap-2">
            {badges.map((b) => (
              <span
                key={b.label}
                className={`inline-flex items-center gap-2 rounded-xs border px-2.5 py-1 text-tabular text-[11px] font-medium
                  ${
                    b.tone === "success"
                      ? "border-success/30 bg-success/10 text-success"
                      : b.tone === "warning"
                        ? "border-warning/30 bg-warning/10 text-warning"
                        : b.tone === "critical"
                          ? "border-critical/40 bg-critical/10 text-critical"
                          : b.tone === "info"
                            ? "border-info/30 bg-info/10 text-info"
                            : "border-border-strong bg-surface-2 text-muted-foreground"
                  }`}
              >
                <StatusDot tone={b.tone} pulse={b.pulse} />
                {b.label}
              </span>
            ))}
          </div>

          <div className="text-overline mb-3 mt-8">Semantic badges</div>
          <div className="flex flex-wrap gap-2">
            <Badge>Default</Badge>
            <Badge variant="secondary">Secondary</Badge>
            <Badge variant="outline">Outline</Badge>
            <Badge className="border-accent/30 bg-accent/10 text-accent" variant="outline">
              <CircleDot className="mr-1 h-3 w-3" /> LIVE
            </Badge>
            <Badge className="border-success/30 bg-success/10 text-success" variant="outline">
              PQ · ML-KEM-768
            </Badge>
            <Badge className="border-warning/30 bg-warning/10 text-warning" variant="outline">
              EPOCH e-1442
            </Badge>
          </div>
        </Panel>

        <Panel>
          <div className="text-overline mb-4">Alert banners</div>
          <div className="space-y-2.5">
            <AlertBanner
              tone="critical"
              icon={AlertTriangle}
              title="UAV-07 certificate revoked"
              body="Peer identity failed ML-DSA verification. Node quarantined from group."
            />
            <AlertBanner
              tone="warning"
              icon={Signal}
              title="Link entropy degraded on LTE-B"
              body="ACPE staging cipher escalation to hybrid suite in 12s."
            />
            <AlertBanner
              tone="success"
              icon={CheckCircle2}
              title="TreeKEM epoch e-1442 committed"
              body="24 members rekeyed in 318 ms. Path length 5."
            />
            <AlertBanner
              tone="info"
              icon={Radio}
              title="ns-3 mirror synchronized"
              body="Simulation topology aligned with live fleet at 04:12:07Z."
            />
          </div>
        </Panel>
      </div>
    </Section>
  );
}

function AlertBanner({
  tone,
  icon: Icon,
  title,
  body,
}: {
  tone: "success" | "warning" | "critical" | "info";
  icon: React.ElementType;
  title: string;
  body: string;
}) {
  const map = {
    success: "border-success/30 bg-success/8 text-success",
    warning: "border-warning/30 bg-warning/8 text-warning",
    critical: "border-critical/40 bg-critical/10 text-critical",
    info: "border-info/30 bg-info/8 text-info",
  } as const;
  return (
    <div
      className={`flex items-start gap-3 rounded-sm border px-3.5 py-3 ${map[tone]}`}
    >
      <Icon className="mt-0.5 h-4 w-4 shrink-0" />
      <div className="min-w-0 flex-1">
        <div className="text-[13px] font-semibold text-foreground">{title}</div>
        <div className="mt-0.5 text-[12px] leading-relaxed text-muted-foreground">
          {body}
        </div>
      </div>
      <button className="text-tabular text-[11px] uppercase tracking-wider text-muted-foreground hover:text-foreground">
        Ack
      </button>
    </div>
  );
}

function CardsSection() {
  return (
    <Section
      id="cards"
      eyebrow="§08 · Cards · KPI · Metrics"
      title="Reading system state at a glance"
      desc="Every card follows the same anatomy: overline label, tabular value, delta, sparkline or micro-viz, footer meta."
    >
      <div className="grid grid-cols-1 gap-4 md:grid-cols-2 lg:grid-cols-4">
        <MetricCard
          label="Fleet online"
          value="24"
          suffix="/ 26"
          delta="+2"
          deltaTone="success"
          footer="24h avg 22.8"
        />
        <MetricCard
          label="Mean handshake"
          value="118"
          suffix="ms"
          delta="-14 ms"
          deltaTone="success"
          footer="Hybrid X25519+ML-KEM-768"
        />
        <MetricCard
          label="Policy escalations"
          value="3"
          delta="+1"
          deltaTone="warning"
          footer="ACPE · last 1h"
        />
        <MetricCard
          label="Cert revocations"
          value="0"
          delta="0"
          deltaTone="neutral"
          footer="CRL synced 04:11Z"
        />
      </div>

      <div className="mt-4 grid grid-cols-1 gap-4 lg:grid-cols-3">
        <UAVCard />
        <SecurityCard />
        <MissionCard />
      </div>
    </Section>
  );
}

function MetricCard({
  label,
  value,
  suffix,
  delta,
  deltaTone,
  footer,
}: {
  label: string;
  value: string;
  suffix?: string;
  delta: string;
  deltaTone: "success" | "warning" | "critical" | "neutral";
  footer: string;
}) {
  const tone = {
    success: "text-success bg-success/10 border-success/30",
    warning: "text-warning bg-warning/10 border-warning/30",
    critical: "text-critical bg-critical/10 border-critical/30",
    neutral: "text-muted-foreground bg-surface-2 border-border-strong",
  }[deltaTone];
  return (
    <div className="panel hud-corner p-5">
      <div className="flex items-center justify-between">
        <div className="text-overline">{label}</div>
        <span
          className={`rounded-xs border px-1.5 py-0.5 text-tabular text-[10.5px] ${tone}`}
        >
          {delta}
        </span>
      </div>
      <div className="mt-3 flex items-baseline gap-1.5">
        <div className="text-tabular text-3xl font-semibold tracking-tight text-foreground">
          {value}
        </div>
        {suffix && (
          <div className="text-tabular text-sm text-muted-foreground">{suffix}</div>
        )}
      </div>
      <Sparkline className="mt-3" />
      <div className="mt-3 text-[11.5px] text-muted-foreground">{footer}</div>
    </div>
  );
}

function Sparkline({ className = "" }: { className?: string }) {
  const points = [8, 12, 10, 16, 14, 20, 18, 24, 22, 28, 26, 32, 30, 38, 34, 42];
  const max = Math.max(...points);
  const w = 240;
  const h = 40;
  const step = w / (points.length - 1);
  const path = points
    .map(
      (p, i) =>
        `${i === 0 ? "M" : "L"} ${(i * step).toFixed(1)} ${(h - (p / max) * (h - 4)).toFixed(1)}`,
    )
    .join(" ");
  return (
    <svg
      viewBox={`0 0 ${w} ${h}`}
      className={`h-10 w-full ${className}`}
      preserveAspectRatio="none"
    >
      <defs>
        <linearGradient id="spark" x1="0" x2="0" y1="0" y2="1">
          <stop offset="0%" stopColor="var(--accent)" stopOpacity="0.4" />
          <stop offset="100%" stopColor="var(--accent)" stopOpacity="0" />
        </linearGradient>
      </defs>
      <path d={`${path} L ${w} ${h} L 0 ${h} Z`} fill="url(#spark)" />
      <path d={path} fill="none" stroke="var(--accent)" strokeWidth="1.25" />
    </svg>
  );
}

function UAVCard() {
  return (
    <div className="panel hud-corner overflow-hidden !p-0">
      <div className="flex items-center justify-between border-b border-border px-5 py-3">
        <div className="flex items-center gap-2.5">
          <div className="flex h-8 w-8 items-center justify-center rounded-sm bg-surface-2 text-accent">
            <Plane className="h-4 w-4" />
          </div>
          <div>
            <div className="text-[13px] font-semibold">
              UAV-014{" "}
              <span className="text-tabular text-muted-foreground">· FALCON</span>
            </div>
            <div className="text-tabular text-[10.5px] text-muted-foreground">
              38.897N · 077.036W · 412 m AGL
            </div>
          </div>
        </div>
        <span className="inline-flex items-center gap-2 rounded-xs border border-success/30 bg-success/10 px-2 py-1 text-tabular text-[10.5px] text-success">
          <StatusDot tone="success" pulse /> ARMED
        </span>
      </div>
      <div className="grid grid-cols-3 divide-x divide-border">
        {[
          ["Battery", "82%", "success"],
          ["Link", "-64 dBm", "success"],
          ["RTT", "128 ms", "warning"],
        ].map(([k, v, t]) => (
          <div key={k} className="px-5 py-4">
            <div className="text-overline">{k}</div>
            <div
              className={`text-tabular mt-1 text-lg font-semibold ${
                t === "success"
                  ? "text-foreground"
                  : t === "warning"
                    ? "text-warning"
                    : "text-critical"
              }`}
            >
              {v}
            </div>
          </div>
        ))}
      </div>
      <div className="border-t border-border px-5 py-3">
        <div className="flex items-center justify-between text-tabular text-[11px]">
          <span className="text-muted-foreground">CIPHER</span>
          <span className="text-accent">X25519+ML-KEM-768</span>
        </div>
        <div className="mt-1.5 flex items-center justify-between text-tabular text-[11px]">
          <span className="text-muted-foreground">EPOCH</span>
          <span>e-1442 · 04m ago</span>
        </div>
      </div>
    </div>
  );
}

function SecurityCard() {
  return (
    <div className="panel !p-0">
      <div className="flex items-center gap-2.5 border-b border-border px-5 py-3">
        <ShieldCheck className="h-4 w-4 text-accent" />
        <div className="text-[13px] font-semibold">Cryptographic posture</div>
        <span className="ml-auto text-overline">ACPE · L3</span>
      </div>
      <div className="space-y-3 px-5 py-4">
        {[
          ["KEM", "ML-KEM-768", "success"],
          ["SIG", "ML-DSA-65", "success"],
          ["KDF", "HKDF-SHA-384", "success"],
          ["AEAD", "AES-256-GCM", "success"],
          ["GROUP", "TreeKEM · path 5", "info"],
        ].map(([k, v, t]) => (
          <div key={k} className="flex items-center justify-between">
            <div className="text-tabular text-[11px] uppercase tracking-wider text-muted-foreground">
              {k}
            </div>
            <div className="flex items-center gap-2">
              <StatusDot tone={t as "success" | "info"} />
              <span className="text-tabular text-[12px]">{v}</span>
            </div>
          </div>
        ))}
      </div>
      <div className="flex items-center justify-between border-t border-border px-5 py-3">
        <span className="text-tabular text-[11px] text-muted-foreground">
          Next rotation
        </span>
        <span className="text-tabular text-[12px]">04:00:00Z · in 03:47</span>
      </div>
    </div>
  );
}

function MissionCard() {
  return (
    <div className="panel !p-0">
      <div className="flex items-center justify-between border-b border-border px-5 py-3">
        <div className="flex items-center gap-2.5">
          <Radar className="h-4 w-4 text-accent" />
          <div className="text-[13px] font-semibold">MSN-2026-0708-A</div>
        </div>
        <span className="text-overline">PHASE · 03 / 07</span>
      </div>
      <div className="px-5 py-4">
        <div className="text-[13px] font-medium text-foreground">
          Perimeter reconnaissance · Grid delta-4
        </div>
        <div className="mt-1 text-[11.5px] text-muted-foreground">
          6 UAVs · 42 min elapsed · 78 min remaining
        </div>
        <div className="mt-4">
          <Progress value={42} className="h-1.5" />
          <div className="mt-2 flex justify-between text-tabular text-[11px] text-muted-foreground">
            <span>42%</span>
            <span>ETA 21:14Z</span>
          </div>
        </div>
      </div>
      <div className="flex items-center justify-between border-t border-border px-5 py-3">
        <Button variant="ghost" size="sm" className="h-7 gap-1.5 text-[12px]">
          <Terminal className="h-3.5 w-3.5" /> Console
        </Button>
        <Button size="sm" className="h-7 gap-1.5 text-[12px]">
          Detail <ArrowUpRight className="h-3.5 w-3.5" />
        </Button>
      </div>
    </div>
  );
}

function MissionComponents() {
  return (
    <Section
      id="mission"
      eyebrow="§09 · Mission components"
      title="Topology · TreeKEM · Timeline"
      desc="Domain-specific components composed from the base tokens."
    >
      <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
        <Panel hud>
          <div className="mb-3 flex items-center justify-between">
            <div>
              <div className="text-overline">Network topology</div>
              <div className="mt-1 text-[13px] font-semibold">
                CA ↔ GCS ↔ Fleet · live
              </div>
            </div>
            <span className="inline-flex items-center gap-2 text-tabular text-[11px] text-muted-foreground">
              <StatusDot tone="success" pulse /> 24 links
            </span>
          </div>
          <Topology />
        </Panel>

        <Panel hud>
          <div className="mb-3 flex items-center justify-between">
            <div>
              <div className="text-overline">TreeKEM group state</div>
              <div className="mt-1 text-[13px] font-semibold">
                Epoch e-1442 · path len 5
              </div>
            </div>
            <Badge className="border-accent/30 bg-accent/10 text-accent" variant="outline">
              STABLE
            </Badge>
          </div>
          <TreeKEM />
        </Panel>

        <Panel className="lg:col-span-2">
          <div className="mb-4 flex items-center justify-between">
            <div>
              <div className="text-overline">Event timeline · last 6 min</div>
              <div className="mt-1 text-[13px] font-semibold">
                Cryptographic & mission events
              </div>
            </div>
            <div className="flex items-center gap-2">
              <Tooltip>
                <TooltipTrigger asChild>
                  <Button size="sm" variant="outline" className="h-7 gap-1.5">
                    <Activity className="h-3.5 w-3.5" /> Live
                  </Button>
                </TooltipTrigger>
                <TooltipContent>Pause stream</TooltipContent>
              </Tooltip>
            </div>
          </div>
          <Timeline />
        </Panel>
      </div>
    </Section>
  );
}

function Topology() {
  const nodes: {
    id: string;
    x: number;
    y: number;
    kind: "ca" | "gcs" | "uav";
    label: string;
    tone: "success" | "warning" | "critical";
  }[] = [
    { id: "ca", x: 50, y: 90, kind: "ca", label: "CA", tone: "success" },
    { id: "gcs", x: 260, y: 90, kind: "gcs", label: "GCS", tone: "success" },
    { id: "u1", x: 430, y: 30, kind: "uav", label: "UAV-01", tone: "success" },
    { id: "u2", x: 480, y: 90, kind: "uav", label: "UAV-14", tone: "warning" },
    { id: "u3", x: 430, y: 150, kind: "uav", label: "UAV-22", tone: "success" },
    { id: "u4", x: 540, y: 45, kind: "uav", label: "UAV-07", tone: "critical" },
    { id: "u5", x: 560, y: 135, kind: "uav", label: "UAV-19", tone: "success" },
  ];
  const links: [string, string][] = [
    ["ca", "gcs"],
    ["gcs", "u1"],
    ["gcs", "u2"],
    ["gcs", "u3"],
    ["u2", "u4"],
    ["u2", "u5"],
  ];
  const byId = Object.fromEntries(nodes.map((n) => [n.id, n]));
  const toneColor = {
    success: "var(--success)",
    warning: "var(--warning)",
    critical: "var(--critical)",
  } as const;
  return (
    <div className="grid-bg relative h-[240px] overflow-hidden rounded-sm border border-border-subtle bg-surface/40">
      <svg viewBox="0 0 620 200" className="absolute inset-0 h-full w-full">
        {links.map(([a, b], i) => {
          const A = byId[a];
          const B = byId[b];
          return (
            <line
              key={i}
              x1={A.x}
              y1={A.y}
              x2={B.x}
              y2={B.y}
              stroke="var(--accent)"
              strokeOpacity="0.4"
              strokeDasharray="3 3"
              strokeWidth="1"
            />
          );
        })}
        {nodes.map((n) => (
          <g key={n.id}>
            <circle
              cx={n.x}
              cy={n.y}
              r={n.kind === "uav" ? 6 : 9}
              fill={toneColor[n.tone]}
            />
            <circle
              cx={n.x}
              cy={n.y}
              r={n.kind === "uav" ? 12 : 15}
              fill="none"
              stroke={toneColor[n.tone]}
              strokeOpacity="0.35"
              strokeWidth="1"
            />
            <text
              x={n.x}
              y={n.y + (n.kind === "uav" ? 24 : 28)}
              textAnchor="middle"
              fill="var(--muted-foreground)"
              fontFamily="var(--font-mono)"
              fontSize="10"
            >
              {n.label}
            </text>
          </g>
        ))}
      </svg>
      <div className="absolute bottom-2 left-3 flex gap-3 text-tabular text-[10px] text-muted-foreground">
        <span className="inline-flex items-center gap-1.5">
          <Satellite className="h-3 w-3" /> CA
        </span>
        <span className="inline-flex items-center gap-1.5">
          <Cpu className="h-3 w-3" /> GCS
        </span>
        <span className="inline-flex items-center gap-1.5">
          <Plane className="h-3 w-3" /> UAV
        </span>
      </div>
    </div>
  );
}

function TreeKEM() {
  return (
    <div className="grid-bg relative h-[240px] overflow-hidden rounded-sm border border-border-subtle bg-surface/40 p-4">
      <svg viewBox="0 0 480 210" className="h-full w-full">
        {/* edges */}
        {[
          [240, 30, 120, 90],
          [240, 30, 360, 90],
          [120, 90, 60, 150],
          [120, 90, 180, 150],
          [360, 90, 300, 150],
          [360, 90, 420, 150],
          [60, 150, 30, 200],
          [60, 150, 90, 200],
          [180, 150, 150, 200],
          [180, 150, 210, 200],
          [300, 150, 270, 200],
          [300, 150, 330, 200],
          [420, 150, 390, 200],
          [420, 150, 450, 200],
        ].map(([x1, y1, x2, y2], i) => (
          <line
            key={i}
            x1={x1}
            y1={y1}
            x2={x2}
            y2={y2}
            stroke="var(--border-strong)"
            strokeWidth="1"
          />
        ))}
        {/* internal nodes */}
        {[
          [240, 30, "root"],
          [120, 90, ""],
          [360, 90, ""],
          [60, 150, ""],
          [180, 150, ""],
          [300, 150, ""],
          [420, 150, ""],
        ].map(([x, y, l], i) => (
          <g key={"i" + i}>
            <rect
              x={(x as number) - 8}
              y={(y as number) - 8}
              width="16"
              height="16"
              fill="var(--surface-3)"
              stroke="var(--accent)"
              strokeWidth="1"
              rx="2"
            />
            {l && (
              <text
                x={x as number}
                y={(y as number) - 14}
                textAnchor="middle"
                fill="var(--accent)"
                fontFamily="var(--font-mono)"
                fontSize="9"
              >
                {l as string}
              </text>
            )}
          </g>
        ))}
        {/* leaves */}
        {[30, 90, 150, 210, 270, 330, 390, 450].map((x, i) => (
          <g key={"l" + i}>
            <circle
              cx={x}
              cy={200}
              r="6"
              fill={i === 6 ? "var(--critical)" : "var(--success)"}
            />
            <text
              x={x}
              y={220}
              textAnchor="middle"
              fill="var(--muted-foreground)"
              fontFamily="var(--font-mono)"
              fontSize="8"
            >
              U{String(i + 1).padStart(2, "0")}
            </text>
          </g>
        ))}
      </svg>
      <div className="absolute right-3 top-3 flex flex-col gap-1 text-tabular text-[10px]">
        <span className="inline-flex items-center gap-1.5">
          <span className="h-1.5 w-1.5 rounded-full bg-success" /> keyed
        </span>
        <span className="inline-flex items-center gap-1.5">
          <span className="h-1.5 w-1.5 rounded-full bg-critical" /> revoked
        </span>
      </div>
    </div>
  );
}

function Timeline() {
  const events = [
    {
      t: "04:12:07Z",
      tone: "success" as const,
      title: "Group rekey committed",
      body: "Epoch e-1442 · 24 members · path length 5 · 318 ms",
      icon: Key,
    },
    {
      t: "04:11:42Z",
      tone: "warning" as const,
      title: "ACPE elevated policy to L3",
      body: "Trigger: link entropy < 0.62 on LTE-B",
      icon: Zap,
    },
    {
      t: "04:11:03Z",
      tone: "critical" as const,
      title: "UAV-07 certificate revoked",
      body: "ML-DSA verification failed · quarantined from group",
      icon: AlertTriangle,
    },
    {
      t: "04:09:55Z",
      tone: "info" as const,
      title: "ns-3 mirror synchronized",
      body: "Topology aligned · 26 nodes · 42 links",
      icon: Network,
    },
    {
      t: "04:08:12Z",
      tone: "success" as const,
      title: "Handshake · UAV-19",
      body: "X25519+ML-KEM-768 · 118 ms · verified",
      icon: ShieldCheck,
    },
  ];
  return (
    <ol className="relative ml-2 border-l border-border-strong">
      {events.map((e, i) => (
        <li key={i} className="relative pb-5 pl-6 last:pb-0">
          <span
            className={`absolute -left-[7px] top-0.5 h-3 w-3 rounded-full border-2 border-background
              ${
                e.tone === "success"
                  ? "bg-success"
                  : e.tone === "warning"
                    ? "bg-warning"
                    : e.tone === "critical"
                      ? "bg-critical"
                      : "bg-info"
              }`}
          />
          <div className="flex items-center gap-2 text-tabular text-[11px] text-muted-foreground">
            <span>{e.t}</span>
            <span className="h-3 w-px bg-border" />
            <e.icon className="h-3 w-3" />
          </div>
          <div className="mt-0.5 text-[13px] font-medium text-foreground">
            {e.title}
          </div>
          <div className="text-[12px] text-muted-foreground">{e.body}</div>
        </li>
      ))}
    </ol>
  );
}

function DataDisplay() {
  const rows = [
    ["UAV-01", "SPARROW", "success", "82%", "-58 dBm", "104 ms", "ML-KEM-768", "e-1442"],
    ["UAV-07", "RAVEN", "critical", "—", "—", "—", "REVOKED", "e-1441"],
    ["UAV-14", "FALCON", "warning", "64%", "-72 dBm", "218 ms", "ML-KEM-768", "e-1442"],
    ["UAV-19", "OSPREY", "success", "91%", "-54 dBm", "88 ms", "ML-KEM-768", "e-1442"],
    ["UAV-22", "KESTREL", "success", "77%", "-61 dBm", "132 ms", "ML-KEM-768", "e-1442"],
  ] as const;
  return (
    <Section
      id="data"
      eyebrow="§10 · Data · Tables · Charts"
      title="Dense, tabular, scannable"
      desc="Monospaced values, aligned units, muted zebra, sticky headers. No decorative row heights."
    >
      <Panel className="!p-0">
        <div className="flex items-center justify-between px-5 py-3">
          <div className="flex items-center gap-2">
            <div className="text-[13px] font-semibold">Fleet roster</div>
            <Badge variant="outline" className="text-tabular">
              5 / 26
            </Badge>
          </div>
          <div className="flex items-center gap-2">
            <Input
              placeholder="Filter · callsign, epoch, cipher…"
              className="h-8 w-72 text-xs"
            />
            <Button size="sm" variant="outline" className="h-8">
              Export
            </Button>
          </div>
        </div>
        <div className="overflow-x-auto border-t border-border">
          <Table>
            <TableHeader>
              <TableRow className="border-border hover:bg-transparent">
                {["ID", "Callsign", "State", "Batt", "Link", "RTT", "KEM", "Epoch"].map(
                  (h) => (
                    <TableHead key={h} className="text-overline">
                      {h}
                    </TableHead>
                  ),
                )}
              </TableRow>
            </TableHeader>
            <TableBody>
              {rows.map((r, i) => (
                <TableRow key={i} className="border-border/60">
                  <TableCell className="text-tabular font-medium">{r[0]}</TableCell>
                  <TableCell className="text-tabular text-muted-foreground">
                    {r[1]}
                  </TableCell>
                  <TableCell>
                    <span
                      className={`inline-flex items-center gap-1.5 rounded-xs border px-1.5 py-0.5 text-tabular text-[10.5px]
                        ${
                          r[2] === "success"
                            ? "border-success/30 bg-success/10 text-success"
                            : r[2] === "warning"
                              ? "border-warning/30 bg-warning/10 text-warning"
                              : "border-critical/40 bg-critical/10 text-critical"
                        }`}
                    >
                      <StatusDot
                        tone={r[2] as "success" | "warning" | "critical"}
                      />
                      {r[2] === "success"
                        ? "NOMINAL"
                        : r[2] === "warning"
                          ? "DEGRADED"
                          : "FAULT"}
                    </span>
                  </TableCell>
                  <TableCell className="text-tabular">{r[3]}</TableCell>
                  <TableCell className="text-tabular">{r[4]}</TableCell>
                  <TableCell className="text-tabular">{r[5]}</TableCell>
                  <TableCell className="text-tabular text-accent">{r[6]}</TableCell>
                  <TableCell className="text-tabular text-muted-foreground">
                    {r[7]}
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </div>
      </Panel>

      <div className="mt-4 grid grid-cols-1 gap-4 lg:grid-cols-2">
        <Panel>
          <div className="mb-3 flex items-center justify-between">
            <div>
              <div className="text-overline">Handshake latency · p50</div>
              <div className="text-[13px] font-semibold">Last 60 minutes</div>
            </div>
            <div className="text-tabular text-[11px] text-muted-foreground">
              ms
            </div>
          </div>
          <AreaChart />
        </Panel>
        <Panel>
          <div className="mb-3">
            <div className="text-overline">Cipher suite distribution</div>
            <div className="text-[13px] font-semibold">Active handshakes</div>
          </div>
          <div className="space-y-3">
            {[
              ["Hybrid · X25519+ML-KEM-768", 72, "var(--accent)"],
              ["Post-quantum · ML-KEM-1024", 18, "var(--success)"],
              ["Classical · X25519", 10, "var(--warning)"],
            ].map(([label, pct, color]) => (
              <div key={label as string}>
                <div className="mb-1 flex items-center justify-between text-[12px]">
                  <span className="text-foreground">{label as string}</span>
                  <span className="text-tabular text-muted-foreground">
                    {pct as number}%
                  </span>
                </div>
                <div className="h-1.5 overflow-hidden rounded-full bg-surface-2">
                  <div
                    className="h-full rounded-full"
                    style={{
                      width: `${pct}%`,
                      background: color as string,
                    }}
                  />
                </div>
              </div>
            ))}
          </div>
        </Panel>
      </div>
    </Section>
  );
}

function AreaChart() {
  const points = [
    22, 24, 21, 26, 30, 28, 34, 40, 36, 32, 38, 44, 42, 46, 50, 44, 40, 36, 30,
    28, 26, 24, 22, 26,
  ];
  const w = 560;
  const h = 140;
  const max = Math.max(...points) * 1.1;
  const step = w / (points.length - 1);
  const path = points
    .map(
      (p, i) =>
        `${i === 0 ? "M" : "L"} ${(i * step).toFixed(1)} ${(h - (p / max) * (h - 10)).toFixed(1)}`,
    )
    .join(" ");
  return (
    <svg viewBox={`0 0 ${w} ${h}`} className="h-36 w-full">
      <defs>
        <linearGradient id="area" x1="0" x2="0" y1="0" y2="1">
          <stop offset="0%" stopColor="var(--accent)" stopOpacity="0.35" />
          <stop offset="100%" stopColor="var(--accent)" stopOpacity="0" />
        </linearGradient>
      </defs>
      {[0.25, 0.5, 0.75].map((r) => (
        <line
          key={r}
          x1="0"
          x2={w}
          y1={h * r}
          y2={h * r}
          stroke="var(--border)"
          strokeDasharray="2 4"
        />
      ))}
      <path d={`${path} L ${w} ${h} L 0 ${h} Z`} fill="url(#area)" />
      <path d={path} fill="none" stroke="var(--accent)" strokeWidth="1.5" />
    </svg>
  );
}

function FeedbackStates() {
  return (
    <Section
      id="feedback"
      eyebrow="§11 · Feedback · Empty · Loading · Error"
      title="Every non-happy path is designed"
      desc="Empty, loading and error states are first-class views — never afterthoughts."
    >
      <div className="grid grid-cols-1 gap-4 md:grid-cols-3">
        <Panel>
          <div className="text-overline mb-3">Skeleton · loading</div>
          <div className="space-y-3">
            <div className="flex items-center gap-3">
              <Skeleton className="h-8 w-8 rounded-sm" />
              <div className="flex-1 space-y-2">
                <Skeleton className="h-3 w-2/3" />
                <Skeleton className="h-2.5 w-1/2" />
              </div>
            </div>
            <Skeleton className="h-24 w-full" />
            <div className="grid grid-cols-3 gap-2">
              <Skeleton className="h-10" />
              <Skeleton className="h-10" />
              <Skeleton className="h-10" />
            </div>
          </div>
        </Panel>

        <Panel>
          <div className="text-overline mb-3">Empty state</div>
          <div className="flex flex-col items-center py-6 text-center">
            <div className="flex h-12 w-12 items-center justify-center rounded-sm border border-dashed border-border-strong text-muted-foreground">
              <Radar className="h-6 w-6" />
            </div>
            <div className="mt-4 text-[13px] font-semibold">No mission active</div>
            <p className="mt-1 max-w-xs text-[12px] text-muted-foreground">
              Assign a fleet, define waypoints and select a cryptographic policy to
              begin.
            </p>
            <Button size="sm" className="mt-4">
              New mission
            </Button>
          </div>
        </Panel>

        <Panel>
          <div className="text-overline mb-3">Error state</div>
          <div className="flex flex-col items-center py-6 text-center">
            <div className="flex h-12 w-12 items-center justify-center rounded-sm border border-critical/40 bg-critical/10 text-critical">
              <AlertTriangle className="h-6 w-6" />
            </div>
            <div className="mt-4 text-[13px] font-semibold">
              CA unreachable
            </div>
            <p className="mt-1 max-w-xs text-[12px] text-muted-foreground">
              Certificate authority did not respond within 4000 ms. Cached CRL in
              use.
            </p>
            <div className="mt-4 flex gap-2">
              <Button size="sm" variant="outline">
                Diagnostics
              </Button>
              <Button size="sm">Retry</Button>
            </div>
          </div>
        </Panel>
      </div>

      <div className="mt-4">
        <Panel>
          <div className="text-overline mb-3">Progress · determinate & indeterminate</div>
          <div className="grid grid-cols-1 gap-6 md:grid-cols-3">
            <div>
              <div className="mb-1.5 flex justify-between text-[12px]">
                <span>Key encapsulation</span>
                <span className="text-tabular text-muted-foreground">64%</span>
              </div>
              <Progress value={64} className="h-1.5" />
            </div>
            <div>
              <div className="mb-1.5 flex justify-between text-[12px]">
                <span>Certificate reissue</span>
                <span className="text-tabular text-muted-foreground">18%</span>
              </div>
              <Progress value={18} className="h-1.5" />
            </div>
            <div>
              <div className="mb-1.5 flex justify-between text-[12px]">
                <span>Telemetry stream</span>
                <span className="text-tabular text-muted-foreground">live</span>
              </div>
              <div className="relative h-1.5 overflow-hidden rounded-full bg-surface-2">
                <div className="absolute inset-y-0 w-1/3 animate-[ticker_2s_linear_infinite] rounded-full bg-accent/70" />
              </div>
            </div>
          </div>
        </Panel>
      </div>
    </Section>
  );
}

function Architecture() {
  const groups = [
    {
      label: "Command surfaces",
      items: [
        "Mission Overview",
        "Fleet Console",
        "Waypoint Planner",
        "Live Telemetry",
      ],
    },
    {
      label: "Security surfaces",
      items: [
        "Certificate Authority",
        "TreeKEM Group State",
        "ACPE Policy Console",
        "Audit & Compliance",
      ],
    },
    {
      label: "Infrastructure",
      items: [
        "Network Topology",
        "Link Analytics · LTE / Ethernet",
        "MAVLink Traffic Inspector",
        "Hardware Health",
      ],
    },
    {
      label: "Research",
      items: [
        "ns-3 Simulation",
        "Scenario Library",
        "Metrics Explorer",
        "Datasets & Exports",
      ],
    },
  ];
  return (
    <Section
      id="architecture"
      eyebrow="§12 · Information architecture"
      title="Where the design system will be used"
      desc="Four surface families share this design language. Every screen is composed from the components above."
    >
      <div className="grid grid-cols-1 gap-4 md:grid-cols-2 lg:grid-cols-4">
        {groups.map((g) => (
          <Panel key={g.label}>
            <div className="text-overline mb-3">{g.label}</div>
            <ul className="space-y-2">
              {g.items.map((i) => (
                <li
                  key={i}
                  className="flex items-center justify-between rounded-xs px-2 py-1.5 text-[13px] text-foreground hover:bg-surface-2"
                >
                  <span>{i}</span>
                  <ChevronRight className="h-3.5 w-3.5 text-muted-foreground" />
                </li>
              ))}
            </ul>
          </Panel>
        ))}
      </div>
    </Section>
  );
}

function Footer() {
  return (
    <footer className="mt-16 border-t border-border/70 py-8">
      <div className="flex flex-col items-start justify-between gap-4 md:flex-row md:items-center">
        <div className="flex items-center gap-3">
          <div className="flex h-7 w-7 items-center justify-center rounded-sm bg-gradient-to-br from-accent to-primary">
            <ShieldCheck className="h-3.5 w-3.5 text-background" />
          </div>
          <div className="text-tabular text-[11px] text-muted-foreground">
            AETHER-PQ · Design System v1.0 · Rev 01 · 2026.07.08
          </div>
        </div>
        <div className="text-tabular text-[11px] text-muted-foreground">
          Restricted · For research and operational use only
        </div>
      </div>
    </footer>
  );
}
