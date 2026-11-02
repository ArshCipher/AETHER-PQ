import { Area, AreaChart, Bar, BarChart, Line, LineChart, ResponsiveContainer, Tooltip, XAxis, YAxis, CartesianGrid } from "recharts";

export type Point = { t: number; v: number };

/** Compact sparkline for KPI cards. */
export function Sparkline({
  data,
  tone = "primary",
  height = 44,
}: {
  data: Point[];
  tone?: "primary" | "success" | "warning" | "critical" | "neutral";
  height?: number;
}) {
  const strokeVar =
    tone === "success" ? "var(--color-success)"
    : tone === "warning" ? "var(--color-warning)"
    : tone === "critical" ? "var(--color-critical)"
    : tone === "neutral" ? "var(--color-muted-foreground)"
    : "var(--color-primary)";
  const id = `spark-${tone}-${Math.random().toString(36).slice(2, 7)}`;
  return (
    <ResponsiveContainer width="100%" height={height}>
      <AreaChart data={data} margin={{ top: 2, right: 0, bottom: 0, left: 0 }}>
        <defs>
          <linearGradient id={id} x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stopColor={strokeVar} stopOpacity={0.18} />
            <stop offset="100%" stopColor={strokeVar} stopOpacity={0} />
          </linearGradient>
        </defs>
        <Area type="monotone" dataKey="v" stroke={strokeVar} strokeWidth={1.5} fill={`url(#${id})`} isAnimationActive animationDuration={600} />
      </AreaChart>
    </ResponsiveContainer>
  );
}

/** Full professional line chart with axes and grid. */
export function ProChart({
  data,
  unit = "",
  tone = "primary",
  height = 220,
  domain,
}: {
  data: Point[];
  unit?: string;
  tone?: "primary" | "success" | "warning" | "critical" | "neutral";
  height?: number;
  domain?: [number | "auto", number | "auto"];
}) {
  const stroke =
    tone === "success" ? "var(--color-success)"
    : tone === "warning" ? "var(--color-warning)"
    : tone === "critical" ? "var(--color-critical)"
    : tone === "neutral" ? "var(--color-muted-foreground)"
    : "var(--color-primary)";
  return (
    <ResponsiveContainer width="100%" height={height}>
      <LineChart data={data} margin={{ top: 8, right: 12, bottom: 4, left: 4 }}>
        <CartesianGrid stroke="var(--color-border)" strokeDasharray="2 4" vertical={false} />
        <XAxis
          dataKey="t"
          tick={{ fill: "var(--color-muted-foreground)", fontSize: 11, fontFamily: "var(--font-mono)" }}
          tickLine={false}
          axisLine={{ stroke: "var(--color-border)" }}
          tickFormatter={(v) => `-${((60 - v) * 5) | 0}s`}
          interval={9}
        />
        <YAxis
          tick={{ fill: "var(--color-muted-foreground)", fontSize: 11, fontFamily: "var(--font-mono)" }}
          tickLine={false}
          axisLine={false}
          width={44}
          domain={domain}
          tickFormatter={(v) => `${v}${unit}`}
        />
        <Tooltip
          contentStyle={{
            background: "var(--color-background)",
            border: "1px solid var(--color-border)",
            borderRadius: 6,
            fontSize: 12,
            boxShadow: "var(--shadow-md)",
          }}
          labelFormatter={(v) => `t-${((60 - Number(v)) * 5) | 0}s`}
          formatter={(v) => [`${v}${unit}`, "value"]}
        />
        <Line type="monotone" dataKey="v" stroke={stroke} strokeWidth={1.75} dot={false} isAnimationActive animationDuration={500} />
      </LineChart>
    </ResponsiveContainer>
  );
}

/** Bar chart for distribution / bandwidth-style. */
export function ProBars({
  data,
  unit = "",
  tone = "primary",
  height = 180,
}: {
  data: Point[];
  unit?: string;
  tone?: "primary" | "success" | "warning" | "critical" | "neutral";
  height?: number;
}) {
  const fill =
    tone === "success" ? "var(--color-success)"
    : tone === "warning" ? "var(--color-warning)"
    : tone === "critical" ? "var(--color-critical)"
    : tone === "neutral" ? "var(--color-muted-foreground)"
    : "var(--color-primary)";
  return (
    <ResponsiveContainer width="100%" height={height}>
      <BarChart data={data} margin={{ top: 8, right: 12, bottom: 4, left: 4 }}>
        <CartesianGrid stroke="var(--color-border)" strokeDasharray="2 4" vertical={false} />
        <XAxis dataKey="t" tick={{ fill: "var(--color-muted-foreground)", fontSize: 11, fontFamily: "var(--font-mono)" }} tickLine={false} axisLine={{ stroke: "var(--color-border)" }} tickFormatter={(v) => `-${((60 - v) * 5) | 0}s`} interval={9} />
        <YAxis tick={{ fill: "var(--color-muted-foreground)", fontSize: 11, fontFamily: "var(--font-mono)" }} tickLine={false} axisLine={false} width={44} tickFormatter={(v) => `${v}${unit}`} />
        <Tooltip contentStyle={{ background: "var(--color-background)", border: "1px solid var(--color-border)", borderRadius: 6, fontSize: 12 }} formatter={(v) => [`${v}${unit}`, "value"]} />
        <Bar dataKey="v" fill={fill} radius={[2, 2, 0, 0]} isAnimationActive animationDuration={500} />
      </BarChart>
    </ResponsiveContainer>
  );
}
