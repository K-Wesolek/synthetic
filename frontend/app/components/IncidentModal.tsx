"use client";

import { useEffect } from "react";
import type { Incident } from "@/lib/api";
import {
  detailFor,
  type ContractRef,
  type IncidentDetail,
  type TimelineEntry,
} from "@/lib/incident-details";
import { ClassChip, CopyButton, fmtAddress, fmtUSDLong, fmtUSDCompact } from "./ui";

function MetaRow({ label, value }: { label: string; value: React.ReactNode }) {
  return (
    <div className="flex items-baseline gap-3 py-1.5">
      <span className="text-2xs uppercase tracking-wider text-fg-tertiary font-mono w-32 flex-shrink-0">
        {label}
      </span>
      <span className="text-xs text-fg-secondary min-w-0">{value}</span>
    </div>
  );
}

function ContractRefRow({ c }: { c: ContractRef }) {
  return (
    <div className="flex items-center gap-3 py-1.5 border-t border-border first:border-t-0">
      <div className="flex-1 min-w-0">
        <div className="text-xs text-fg-primary">{c.label}</div>
        {c.role && (
          <div className="text-2xs text-fg-tertiary mt-0.5">{c.role}</div>
        )}
      </div>
      <div className="font-mono text-2xs text-fg-secondary">
        <span title={c.address}>{fmtAddress(c.address, 6, 4)}</span>
      </div>
      <CopyButton value={c.address} />
    </div>
  );
}

function Timeline({ entries }: { entries: TimelineEntry[] }) {
  return (
    <ul className="space-y-2">
      {entries.map((e, i) => (
        <li key={i} className="flex gap-3 text-xs">
          <span className="font-mono text-2xs text-fg-tertiary w-32 flex-shrink-0 pt-0.5 uppercase tracking-wider">
            {e.time}
          </span>
          <span className="text-fg-secondary leading-relaxed">{e.event}</span>
        </li>
      ))}
    </ul>
  );
}

function Section({
  title,
  children,
}: {
  title: string;
  children: React.ReactNode;
}) {
  return (
    <section className="border-t border-border pt-5 mt-5">
      <h3 className="text-2xs uppercase tracking-wider text-fg-tertiary font-mono mb-3">
        {title}
      </h3>
      {children}
    </section>
  );
}

function FullDetail({
  incident,
  detail,
}: {
  incident: Incident;
  detail: IncidentDetail;
}) {
  return (
    <>
      {/* Plain language */}
      <section className="space-y-3">
        <h3 className="text-2xs uppercase tracking-wider text-fg-tertiary font-mono">
          Plain language
        </h3>
        {detail.plain_language.map((p, i) => (
          <p key={i} className="text-sm text-fg-secondary leading-relaxed">
            {p}
          </p>
        ))}
      </section>

      {/* Technical mechanism */}
      <Section title="Technical mechanism">
        <ul className="space-y-2">
          {detail.technical.map((t, i) => (
            <li key={i} className="text-xs text-fg-secondary leading-relaxed pl-4 relative">
              <span className="absolute left-0 top-2 w-1.5 h-px bg-fg-muted" />
              {t}
            </li>
          ))}
        </ul>
      </Section>

      {/* Forensic metadata */}
      <Section title="Forensics">
        <div className="space-y-0.5">
          {detail.layer && <MetaRow label="Layer" value={detail.layer} />}
          {detail.attack_vector && (
            <MetaRow label="Attack vector" value={detail.attack_vector} />
          )}
          {detail.tokens_lost && (
            <MetaRow label="Tokens lost" value={<span className="font-mono">{detail.tokens_lost}</span>} />
          )}
          <MetaRow
            label="Loss (USD)"
            value={
              <span className="font-mono text-sev-high">
                {detail.loss_usd_label || fmtUSDLong(incident.loss_usd)}
              </span>
            }
          />
          {detail.attacker_address && (
            <MetaRow
              label="Attacker"
              value={
                <span className="font-mono inline-flex items-center gap-2">
                  {fmtAddress(detail.attacker_address, 8, 6)}
                  <CopyButton value={detail.attacker_address} />
                </span>
              }
            />
          )}
        </div>
      </Section>

      {/* Tx hashes */}
      {detail.tx_hashes && detail.tx_hashes.length > 0 && (
        <Section title="Transactions">
          <div className="space-y-1.5">
            {detail.tx_hashes.map((h) => (
              <div key={h} className="flex items-center gap-2 font-mono text-2xs">
                <span className="text-fg-secondary break-all">{h}</span>
                <CopyButton value={h} />
              </div>
            ))}
          </div>
        </Section>
      )}

      {/* Contracts */}
      {detail.contracts_involved && detail.contracts_involved.length > 0 && (
        <Section title="Contracts involved">
          <div className="border border-border rounded-md px-3">
            {detail.contracts_involved.map((c) => (
              <ContractRefRow key={c.address} c={c} />
            ))}
          </div>
        </Section>
      )}

      {/* Timeline */}
      {detail.timeline && detail.timeline.length > 0 && (
        <Section title="Timeline">
          <Timeline entries={detail.timeline} />
        </Section>
      )}

      {/* Consequences */}
      {detail.consequences && detail.consequences.length > 0 && (
        <Section title="Consequences">
          <ul className="space-y-2">
            {detail.consequences.map((c, i) => (
              <li
                key={i}
                className="text-xs text-fg-secondary leading-relaxed pl-4 relative"
              >
                <span className="absolute left-0 top-2 w-1.5 h-px bg-fg-muted" />
                {c}
              </li>
            ))}
          </ul>
        </Section>
      )}

      {/* References */}
      <Section title="References">
        <ul className="space-y-1.5">
          {detail.references.map((r, i) => (
            <li key={i} className="text-xs">
              <a
                href={r.url}
                target="_blank"
                rel="noreferrer"
                className="text-fg-secondary hover:text-fg-primary transition-colors break-all"
              >
                {r.title}{" "}
                <span className="text-fg-muted">↗</span>
              </a>
            </li>
          ))}
        </ul>
      </Section>
    </>
  );
}

function FallbackDetail({ incident }: { incident: Incident }) {
  return (
    <>
      <section className="space-y-3">
        <p className="text-sm text-fg-secondary leading-relaxed">
          {incident.description ||
            "No detailed write-up curated for this incident yet."}
        </p>
      </section>

      <Section title="Forensics">
        <div className="space-y-0.5">
          <MetaRow
            label="Class"
            value={<ClassChip value={incident.vulnerability_class} />}
          />
          <MetaRow label="Date" value={incident.incident_date || "—"} />
          <MetaRow
            label="Loss (USD)"
            value={
              <span className="font-mono text-sev-high">
                {fmtUSDLong(incident.loss_usd)}
              </span>
            }
          />
          {incident.tx_hash && (
            <MetaRow
              label="Tx hash"
              value={
                <span className="font-mono inline-flex items-center gap-2 break-all">
                  {incident.tx_hash}
                  <CopyButton value={incident.tx_hash} />
                </span>
              }
            />
          )}
        </div>
      </Section>

      {incident.source_url && (
        <Section title="Source">
          <a
            href={incident.source_url}
            target="_blank"
            rel="noreferrer"
            className="text-xs text-fg-secondary hover:text-fg-primary transition-colors break-all"
          >
            {incident.source_url} <span className="text-fg-muted">↗</span>
          </a>
        </Section>
      )}
    </>
  );
}

export default function IncidentModal({
  incident,
  open,
  onClose,
}: {
  incident: Incident | null;
  open: boolean;
  onClose: () => void;
}) {
  useEffect(() => {
    if (!open) return;
    function onKey(e: KeyboardEvent) {
      if (e.key === "Escape") onClose();
    }
    document.addEventListener("keydown", onKey);
    document.body.style.overflow = "hidden";
    return () => {
      document.removeEventListener("keydown", onKey);
      document.body.style.overflow = "";
    };
  }, [open, onClose]);

  if (!open || !incident) return null;

  const detail = detailFor(incident);
  const headline = detail?.headline || incident.description || "Incident";

  return (
    <div
      className="fixed inset-0 z-50 flex items-start justify-center overflow-y-auto bg-black/70 backdrop-blur-sm p-4 md:p-8"
      onClick={onClose}
    >
      <div
        className="relative w-full max-w-3xl bg-surface border border-border-strong rounded-lg shadow-2xl my-8"
        onClick={(e) => e.stopPropagation()}
      >
        {/* Header */}
        <div className="px-6 py-5 border-b border-border flex items-start justify-between gap-4">
          <div className="min-w-0">
            <div className="flex flex-wrap items-center gap-2 mb-2">
              <ClassChip value={incident.vulnerability_class} />
              <span className="text-2xs uppercase tracking-wider text-fg-tertiary font-mono">
                {incident.incident_date || "—"}
              </span>
              <span className="text-2xs uppercase tracking-wider font-mono">
                <span className="text-fg-tertiary">loss </span>
                <span className="text-sev-high">
                  {fmtUSDCompact(incident.loss_usd)}
                </span>
              </span>
            </div>
            <h2 className="font-serif-display text-2xl text-fg-primary leading-tight">
              {headline}
            </h2>
            {detail?.summary && (
              <p className="text-sm text-fg-secondary mt-2 leading-relaxed">
                {detail.summary}
              </p>
            )}
          </div>
          <button
            type="button"
            onClick={onClose}
            className="text-fg-tertiary hover:text-fg-primary text-2xl leading-none -mt-1 -mr-1 px-2"
            aria-label="Close"
          >
            ×
          </button>
        </div>

        {/* Body */}
        <div className="px-6 py-5">
          {detail ? (
            <FullDetail incident={incident} detail={detail} />
          ) : (
            <FallbackDetail incident={incident} />
          )}
        </div>
      </div>
    </div>
  );
}
