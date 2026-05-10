"use client";

import { useEffect, useState } from "react";
import {
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  Legend,
  Line,
  LineChart,
  Pie,
  PieChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import { fetchStats, type Stats } from "@/lib/api";
import {
  Card,
  CardHeader,
  CHART_AXIS_STYLE,
  CHART_TOOLTIP_STYLE,
  InfoTip,
  SectionIntro,
  SEVERITY_HEX,
  Skeleton,
  fmtInt,
  fmtUSDCompact,
} from "./ui";
import {
  VULN_CLASS_DESCRIPTIONS,
  VULN_CLASS_LABELS,
  LAYER_DESCRIPTIONS,
  LAYER_LABELS,
  ENTITY_DESCRIPTIONS,
} from "@/lib/glossary";

const CLASS_PALETTE = [
  "#e5484d",
  "#f5a524",
  "#eab308",
  "#84cc16",
  "#46a758",
  "#06b6d4",
  "#6ea8fe",
  "#8b8b97",
  "#a855f7",
  "#ec4899",
  "#f43f5e",
  "#8b5cf6",
];

type ChartTooltipExtras = {
  unit?: string;
  formatter?: (v: number, name: string) => string;
  descriptions?: Record<string, string>;
  labelMap?: Record<string, string>;
  // For vertical (horizontal-bar) charts, Recharts sometimes doesn't pass
  // the categorical axis value as `label`. Fall back to payload[0].payload[labelField].
  labelField?: string;
};

function ChartTooltip(
  props: Record<string, unknown> & ChartTooltipExtras,
) {
  const {
    active,
    payload,
    label,
    unit = "",
    formatter,
    descriptions,
    labelMap,
    labelField,
  } = props as {
    active?: boolean;
    payload?: Array<{ value: number; name: string; color: string; payload?: Record<string, unknown> }>;
    label?: string | number;
    unit?: string;
    formatter?: (v: number, name: string) => string;
    descriptions?: Record<string, string>;
    labelMap?: Record<string, string>;
    labelField?: string;
  };
  if (!active || !payload || payload.length === 0) return null;
  let labelKey = label !== undefined && label !== "" ? String(label) : "";
  if (!labelKey && labelField) {
    const fallback = payload[0]?.payload?.[labelField];
    if (typeof fallback === "string") labelKey = fallback;
  }
  const prettyLabel = labelMap && labelMap[labelKey] ? labelMap[labelKey] : labelKey;
  const description = descriptions && labelKey ? descriptions[labelKey] : undefined;
  return (
    <div style={{ ...CHART_TOOLTIP_STYLE, maxWidth: 320 }}>
      {labelKey && (
        <div className="text-2xs uppercase tracking-wider text-fg-tertiary mb-1">
          {prettyLabel}
        </div>
      )}
      {payload.map((p, i) => {
        const value = formatter
          ? formatter(p.value, p.name)
          : `${fmtInt(p.value)}${unit}`;
        return (
          <div
            key={i}
            className="flex items-center gap-2 font-mono text-xs"
            style={{ color: "rgb(var(--fg-primary))" }}
          >
            <span
              className="inline-block w-2 h-2 rounded-full"
              style={{ background: p.color }}
            />
            <span className="text-fg-tertiary">{p.name}</span>
            <span>{value}</span>
          </div>
        );
      })}
      {description && (
        <div
          className="mt-2 pt-2 border-t border-border text-fg-secondary"
          style={{ fontSize: 11.5, lineHeight: 1.45, fontWeight: 400 }}
        >
          {description}
        </div>
      )}
    </div>
  );
}

function ChartCard({
  title,
  subtitle,
  children,
  height = 260,
  info,
  infoTitle,
}: {
  title: string;
  subtitle?: string;
  children: React.ReactNode;
  height?: number;
  info?: React.ReactNode;
  infoTitle?: string;
}) {
  const titleNode = info ? (
    <span className="inline-flex items-center gap-2">
      {title}
      <InfoTip title={infoTitle || title} body={info} />
    </span>
  ) : (
    title
  );
  return (
    <Card>
      <CardHeader title={titleNode as unknown as string} subtitle={subtitle} />
      <div className="p-4" style={{ height: height + 32 }}>
        <div style={{ height }}>
          <ResponsiveContainer width="100%" height="100%">
            {children as React.ReactElement}
          </ResponsiveContainer>
        </div>
      </div>
    </Card>
  );
}

export default function Dashboard() {
  const [stats, setStats] = useState<Stats | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    fetchStats()
      .then(setStats)
      .catch((e) => setError(e instanceof Error ? e.message : "load failed"));
  }, []);

  if (error)
    return (
      <div className="bg-sev-high-bg border border-sev-high/30 text-sev-high px-4 py-3 rounded text-sm">
        {error}
      </div>
    );

  if (!stats) {
    return (
      <div className="space-y-4">
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
          <Skeleton className="h-72 lg:col-span-2" />
          <Skeleton className="h-72" />
        </div>
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
          <Skeleton className="h-64" />
          <Skeleton className="h-64" />
        </div>
      </div>
    );
  }

  const incidentByYear: Record<string, { year: string; n: number; loss_usd: number }> = {};
  for (const t of stats.incident_timeline) {
    const cur = incidentByYear[t.year] || { year: t.year, n: 0, loss_usd: 0 };
    cur.n += t.n;
    cur.loss_usd += t.loss_usd;
    incidentByYear[t.year] = cur;
  }
  const timelineData = Object.values(incidentByYear).sort((a, b) =>
    a.year.localeCompare(b.year),
  );

  const classData = stats.by_class.slice(0, 12);
  const layerData = stats.by_layer;
  const compilerData = stats.by_compiler;
  const synthClassData = stats.synthetic_by_class;
  const severityData = stats.severity;

  return (
    <div className="space-y-4">
      <SectionIntro
        tags={["substrate", "anchors", "synthesis"]}
        title="Vulnerability landscape."
        description="Aggregations across the three layers of the dataset — verified contracts, historical incidents, and synthesized vulnerable / patched pairs. Each chart is sourced from the same store agents query through MCP."
      />
      {/* Class breakdown + Severity pie */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        <div className="lg:col-span-2">
          <ChartCard
            title="Findings by vulnerability class"
            subtitle={`${fmtInt(stats.totals.findings)} findings · top 12 classes · hover for plain-language description`}
            height={280}
            info={
              <span>
                {ENTITY_DESCRIPTIONS.findings}
                <br />
                <br />
                Hover any bar to see what that vulnerability class actually means in
                plain language. Same taxonomy used across incidents and synthetic.
              </span>
            }
            infoTitle="Vulnerability class"
          >
            <BarChart data={classData} margin={{ top: 8, right: 12, left: 0, bottom: 80 }}>
              <CartesianGrid stroke="rgb(var(--border))" strokeDasharray="2 4" vertical={false} />
              <XAxis
                dataKey="vulnerability_class"
                {...CHART_AXIS_STYLE}
                angle={-35}
                textAnchor="end"
                interval={0}
                tickLine={false}
                axisLine={{ stroke: "rgb(var(--border))" }}
                tickFormatter={(v) => {
                  const pretty = VULN_CLASS_LABELS[v] || v;
                  return pretty.length > 18 ? pretty.slice(0, 17) + "…" : pretty;
                }}
              />
              <YAxis
                {...CHART_AXIS_STYLE}
                allowDecimals={false}
                tickLine={false}
                axisLine={false}
                width={36}
                tickFormatter={(v) => fmtInt(Number(v))}
              />
              <Tooltip
                cursor={{ fill: "rgb(var(--surface-3))" }}
                content={
                  <ChartTooltip
                    unit=" findings"
                    descriptions={VULN_CLASS_DESCRIPTIONS}
                    labelMap={VULN_CLASS_LABELS}
                    labelField="vulnerability_class"
                  />
                }
              />
              <Bar dataKey="n" name="findings" radius={[2, 2, 0, 0]}>
                {classData.map((_, i) => (
                  <Cell key={i} fill={CLASS_PALETTE[i % CLASS_PALETTE.length]} />
                ))}
              </Bar>
            </BarChart>
          </ChartCard>
        </div>

        <ChartCard
          title="Severity distribution"
          subtitle={`${severityData.length} buckets`}
          height={280}
        >
          <PieChart>
            <Pie
              data={severityData}
              dataKey="n"
              nameKey="severity"
              outerRadius={92}
              innerRadius={56}
              paddingAngle={2}
              stroke="rgb(var(--canvas))"
              strokeWidth={2}
            >
              {severityData.map((s, i) => (
                <Cell key={i} fill={SEVERITY_HEX[s.severity] || "#8b8b97"} />
              ))}
            </Pie>
            <Tooltip
              content={
                <ChartTooltip
                  formatter={(v) => `${fmtInt(v)} findings`}
                />
              }
            />
            <Legend
              verticalAlign="bottom"
              iconType="circle"
              iconSize={8}
              wrapperStyle={{ fontSize: 11, color: "rgb(var(--fg-secondary))" }}
              formatter={(v) => (
                <span className="text-fg-secondary text-2xs uppercase tracking-wider">
                  {v}
                </span>
              )}
            />
          </PieChart>
        </ChartCard>
      </div>

      {/* Layer + Compiler */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        <ChartCard
          title="Findings by architecture layer"
          subtitle="where in the stack the bug lives · hover for description"
          height={220}
          info={
            <span>
              An orthogonal axis to vulnerability class. Same bug class can live
              in different layers (a reentrancy in the source vs. in an integration
              callback is a different fix). Hover any bar to see what that layer means.
            </span>
          }
          infoTitle="Architecture layer"
        >
          <BarChart data={layerData} layout="vertical" margin={{ left: 8, right: 12 }}>
            <CartesianGrid stroke="rgb(var(--border))" strokeDasharray="2 4" horizontal={false} />
            <XAxis
              type="number"
              {...CHART_AXIS_STYLE}
              allowDecimals={false}
              tickLine={false}
              axisLine={false}
              tickFormatter={(v) => fmtInt(Number(v))}
            />
            <YAxis
              type="category"
              dataKey="layer"
              {...CHART_AXIS_STYLE}
              width={130}
              tickLine={false}
              axisLine={false}
              tickFormatter={(v) => LAYER_LABELS[v] || v}
            />
            <Tooltip
              cursor={{ fill: "rgb(var(--surface-3))" }}
              content={
                <ChartTooltip
                  unit=" findings"
                  descriptions={LAYER_DESCRIPTIONS}
                  labelMap={LAYER_LABELS}
                  labelField="layer"
                />
              }
            />
            <Bar dataKey="n" name="findings" fill="#6ea8fe" radius={[0, 2, 2, 0]} />
          </BarChart>
        </ChartCard>

        <ChartCard
          title="Compiler version distribution"
          subtitle="contracts vs. findings, by major version"
          height={220}
        >
          <BarChart data={compilerData} margin={{ top: 8, right: 12, left: 0, bottom: 0 }}>
            <CartesianGrid stroke="rgb(var(--border))" strokeDasharray="2 4" vertical={false} />
            <XAxis
              dataKey="major"
              {...CHART_AXIS_STYLE}
              tickLine={false}
              axisLine={{ stroke: "rgb(var(--border))" }}
            />
            <YAxis
              {...CHART_AXIS_STYLE}
              allowDecimals={false}
              tickLine={false}
              axisLine={false}
              width={36}
              tickFormatter={(v) => fmtInt(Number(v))}
            />
            <Tooltip
              cursor={{ fill: "rgb(var(--surface-3))" }}
              content={<ChartTooltip />}
            />
            <Legend
              iconType="circle"
              iconSize={8}
              wrapperStyle={{ fontSize: 11 }}
              formatter={(v) => (
                <span className="text-fg-secondary text-2xs uppercase tracking-wider">
                  {v}
                </span>
              )}
            />
            <Bar dataKey="contracts" fill="#46a758" radius={[2, 2, 0, 0]} />
            <Bar dataKey="findings" fill="#f5a524" radius={[2, 2, 0, 0]} />
          </BarChart>
        </ChartCard>
      </div>

      {/* Incident timeline + Synthetic by class */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        <ChartCard
          title="Incident timeline"
          subtitle="historical anchors — count vs. realized loss (USD)"
          height={220}
        >
          <LineChart data={timelineData} margin={{ top: 8, right: 12, left: 0, bottom: 0 }}>
            <CartesianGrid stroke="rgb(var(--border))" strokeDasharray="2 4" vertical={false} />
            <XAxis
              dataKey="year"
              {...CHART_AXIS_STYLE}
              tickLine={false}
              axisLine={{ stroke: "rgb(var(--border))" }}
            />
            <YAxis
              yAxisId="left"
              {...CHART_AXIS_STYLE}
              allowDecimals={false}
              tickLine={false}
              axisLine={false}
              width={28}
              tickFormatter={(v) => fmtInt(Number(v))}
            />
            <YAxis
              yAxisId="right"
              orientation="right"
              {...CHART_AXIS_STYLE}
              tickLine={false}
              axisLine={false}
              width={50}
              tickFormatter={(v) => fmtUSDCompact(Number(v))}
            />
            <Tooltip
              content={
                <ChartTooltip
                  formatter={(v, name) =>
                    name === "loss_usd" ? fmtUSDCompact(v) : `${fmtInt(v)} incidents`
                  }
                />
              }
            />
            <Legend
              iconType="circle"
              iconSize={8}
              wrapperStyle={{ fontSize: 11 }}
              formatter={(v) => (
                <span className="text-fg-secondary text-2xs uppercase tracking-wider">
                  {v === "n" ? "incidents" : "loss (usd)"}
                </span>
              )}
            />
            <Line
              yAxisId="left"
              type="monotone"
              dataKey="n"
              stroke="#6ea8fe"
              strokeWidth={1.75}
              dot={{ r: 2, fill: "#6ea8fe" }}
              name="n"
            />
            <Line
              yAxisId="right"
              type="monotone"
              dataKey="loss_usd"
              stroke="#e5484d"
              strokeWidth={1.75}
              dot={{ r: 2, fill: "#e5484d" }}
              name="loss_usd"
            />
          </LineChart>
        </ChartCard>

        <ChartCard
          title="Synthetic cases by class"
          subtitle={`${fmtInt(stats.totals.synthetic_cases)} generated pairs`}
          height={220}
          info={ENTITY_DESCRIPTIONS.synthetic}
          infoTitle="Synthetic"
        >
          <BarChart data={synthClassData} margin={{ top: 8, right: 12, left: 0, bottom: 56 }}>
            <CartesianGrid stroke="rgb(var(--border))" strokeDasharray="2 4" vertical={false} />
            <XAxis
              dataKey="vulnerability_class"
              {...CHART_AXIS_STYLE}
              angle={-25}
              textAnchor="end"
              interval={0}
              tickLine={false}
              axisLine={{ stroke: "rgb(var(--border))" }}
              tickFormatter={(v) => VULN_CLASS_LABELS[v] || v}
            />
            <YAxis
              {...CHART_AXIS_STYLE}
              allowDecimals={false}
              tickLine={false}
              axisLine={false}
              width={28}
              tickFormatter={(v) => fmtInt(Number(v))}
            />
            <Tooltip
              cursor={{ fill: "rgb(var(--surface-3))" }}
              content={
                <ChartTooltip
                  unit=" cases"
                  descriptions={VULN_CLASS_DESCRIPTIONS}
                  labelMap={VULN_CLASS_LABELS}
                  labelField="vulnerability_class"
                />
              }
            />
            <Bar dataKey="n" name="cases" radius={[2, 2, 0, 0]}>
              {synthClassData.map((_, i) => (
                <Cell key={i} fill={CLASS_PALETTE[i % CLASS_PALETTE.length]} />
              ))}
            </Bar>
          </BarChart>
        </ChartCard>
      </div>
    </div>
  );
}
