"use client";

import { useMemo, useState } from "react";
import { AlertTriangle, CheckCircle2, FileSearch, MinusCircle } from "lucide-react";
import { clsx } from "clsx";
import FilePicker from "@/components/FilePicker";
import { detectConfigDate } from "@/lib/date";
import { parseConfigHeader } from "@/lib/fortigate";
import { evaluateUniversalChecks, formatCheckType } from "@/lib/universal-checks";

type FileState = { text: string; name: string; date: ReturnType<typeof detectConfigDate> } | null;
type FilterMode = "all" | "fail" | "manual";

export default function SingleCheckWorkbench() {
  const [file, setFile] = useState<FileState>(null);
  const [filter, setFilter] = useState<FilterMode>("all");

  const header = useMemo(() => (file ? parseConfigHeader(file.text) : null), [file]);
  const versionBelowRecommended = (() => {
    if (!header?.version) return null;
    const parts = header.version.split(".").map((part) => Number(part));
    if (parts.some((part) => Number.isNaN(part))) return null;
    const [major = 0, minor = 0, patch = 0] = parts;
    if (major !== 7) return major < 7;
    if (minor !== 4) return minor < 4;
    return patch < 0;
  })();
  const hasValidVersion = Boolean(header?.version);
  const hasPasswordMask = header?.passwordMask === true;
  const canProceed = Boolean(file && hasValidVersion && hasPasswordMask);
  const blockingIssues = useMemo(() => {
    if (!file) return [];
    const issues: string[] = [];
    if (!hasValidVersion) {
      issues.push("Firmware versie ontbreekt in de header (#config-version=...).");
    }
    if (!hasPasswordMask) {
      issues.push("Dude geen wachtwoorden erin");
    }
    return issues;
  }, [file, hasPasswordMask, hasValidVersion]);

  const results = useMemo(() => {
    if (!file || !canProceed) return [];
    return evaluateUniversalChecks(file.text);
  }, [file, canProceed]);

  const summary = useMemo(() => {
    const pass = results.filter((item) => item.status === "pass").length;
    const fail = results.filter((item) => item.status === "fail").length;
    const manual = results.filter((item) => item.status === "manual").length;
    return { pass, fail, manual, total: results.length };
  }, [results]);

  const visibleResults = useMemo(() => {
    if (filter === "all") return results;
    if (filter === "fail") return results.filter((item) => item.status === "fail");
    return results.filter((item) => item.status === "manual");
  }, [filter, results]);

  const handleFile = (text: string, name: string) => {
    const date = detectConfigDate(text, name);
    setFile({ text, name, date });
  };

  const hasFile = Boolean(file);

  return (
    <div className="w-full space-y-6 animate-in fade-in duration-500">
      <div className="grid grid-cols-1 gap-4">
        <FilePicker
          label="Single Configuration"
          hint="Upload 1 FortiGate .conf of .yaml"
          filename={file?.name ?? null}
          detectedIso={file?.date.iso ?? null}
          detectedSource={file?.date.source ?? null}
          onText={handleFile}
        />
      </div>

      <div className="bg-[#121a08]/80 border border-[#94A807]/20 backdrop-blur-xl shadow-2xl rounded-xl p-6 space-y-6">
        <div className="flex flex-col lg:flex-row lg:items-center lg:justify-between gap-4">
          <div>
            <h2 className="text-lg font-semibold text-[#fcfdec] flex items-center gap-2">
              <FileSearch size={18} className="text-[#FFEB39]" />
              Single Config Checklist
            </h2>
            <p className="text-sm text-[#a3a890] mt-1">
              {hasFile
                ? canProceed
                  ? "Checklist vergeleken met de golden baseline."
                  : "Header ontbreekt of password mask uitgeschakeld."
                : "Upload een configuratie om te starten."}
            </p>
          </div>

          {hasFile && canProceed && (
            <div className="flex flex-wrap gap-2">
              <span className="text-xs px-3 py-1 rounded-full bg-[#243305] border border-[#94A807]/20 text-[#a3a890]">
                Pass: {summary.pass}
              </span>
              <span className="text-xs px-3 py-1 rounded-full bg-[#3d2b05] border border-[#FFEB39]/20 text-[#FFEB39]">
                Fail: {summary.fail}
              </span>
              <span className="text-xs px-3 py-1 rounded-full bg-[#2a2212] border border-[#a3a890]/20 text-[#a3a890]">
                Manual: {summary.manual}
              </span>
            </div>
          )}
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
          <div className="bg-[#0a0e05] border border-[#94A807]/10 rounded-xl p-4 space-y-2">
            <div className="text-xs uppercase tracking-[0.2em] text-[#94A807]/80">Versie</div>
            <div className="text-sm text-[#fcfdec]">{header?.version ?? "Onbekend"}</div>
            {versionBelowRecommended === true && (
              <div className="text-xs text-[#FFB347]">
                Let op: firmwareversie wijkt af van de geadviseerde versie.
              </div>
            )}
          </div>
          <div className="bg-[#0a0e05] border border-[#94A807]/10 rounded-xl p-4 space-y-2">
            <div className="text-xs uppercase tracking-[0.2em] text-[#94A807]/80">Model</div>
            <div className="text-sm text-[#fcfdec]">{header?.model ?? "Onbekend"}</div>
          </div>
          <div className="bg-[#0a0e05] border border-[#94A807]/10 rounded-xl p-4 space-y-2">
            <div className="text-xs uppercase tracking-[0.2em] text-[#94A807]/80">Password mask</div>
            <div className="text-sm text-[#fcfdec]">
              {header?.passwordMask === null
                ? "Onbekend"
                : header?.passwordMask
                  ? "Ingeschakeld"
                  : "Uitgeschakeld"}
            </div>
            {!hasPasswordMask && hasFile && (
              <div className="text-xs text-[#FFB347]">Dude geen wachtwoorden erin</div>
            )}
          </div>
        </div>

        {blockingIssues.length > 0 && (
          <div className="rounded-xl border border-[#FFB347]/30 bg-[#2a1208]/50 px-4 py-3 text-xs text-[#FFB347] space-y-1">
            {blockingIssues.map((issue) => (
              <div key={issue}>{issue}</div>
            ))}
          </div>
        )}

        {hasFile && canProceed && (
          <div className="flex flex-wrap gap-2">
            {(
              [
                { id: "all", label: "Alle checks" },
                { id: "fail", label: "Alleen afwijkingen" },
                { id: "manual", label: "Handmatige checks" },
              ] as const
            ).map((tab) => (
              <button
                key={tab.id}
                onClick={() => setFilter(tab.id)}
                className={clsx(
                  "px-4 py-2 rounded-lg text-xs font-medium transition-all",
                  filter === tab.id
                    ? "bg-[#FFEB39] text-[#243305]"
                    : "bg-[#243305]/50 text-[#a3a890] hover:text-[#fcfdec]"
                )}
              >
                {tab.label}
              </button>
            ))}
          </div>
        )}

        <div className="border border-[#94A807]/10 rounded-xl overflow-hidden">
          <div className="grid grid-cols-[2fr_160px_120px_3fr] text-xs uppercase tracking-[0.2em] bg-[#0a0e05] text-[#94A807]/80 px-4 py-3">
            <div>Check</div>
            <div>Type</div>
            <div>Status</div>
            <div>Bewijs</div>
          </div>
          <div className="max-h-[520px] overflow-auto divide-y divide-[#94A807]/10">
            {visibleResults.length === 0 && (
              <div className="p-6 text-sm text-[#a3a890]">
                {hasFile && !canProceed
                  ? "Header ontbreekt of password mask is uitgeschakeld."
                  : hasFile
                    ? "Geen checks in deze filter."
                    : "Upload een bestand om te starten."}
              </div>
            )}
            {visibleResults.map((item) => (
              <div
                key={item.id}
                className={clsx(
                  "grid grid-cols-[2fr_160px_120px_3fr] gap-3 px-4 py-4 text-sm",
                  item.status === "fail" && "bg-[#2a1208]/40",
                  item.status === "manual" && "bg-[#1a1710]/40"
                )}
              >
                <div className="text-[#fcfdec]">
                  <div>{item.name}</div>
                  {item.section && (
                    <div className="text-xs text-[#a3a890] mt-1">{item.section}</div>
                  )}
                </div>
                <div className="text-[#a3a890]">{formatCheckType(item.type)}</div>
                <div className="flex items-center gap-2">
                  {item.status === "pass" && (
                    <span className="inline-flex items-center gap-1 text-[#94A807]">
                      <CheckCircle2 size={16} /> OK
                    </span>
                  )}
                  {item.status === "fail" && (
                    <span className="inline-flex items-center gap-1 text-[#FFB347]">
                      <AlertTriangle size={16} /> Afwijking
                    </span>
                  )}
                  {item.status === "manual" && (
                    <span className="inline-flex items-center gap-1 text-[#a3a890]">
                      <MinusCircle size={16} /> Handmatig
                    </span>
                  )}
                </div>
                <div className="text-xs text-[#a3a890] whitespace-pre-wrap font-mono">
                  {item.status === "fail" && (item.evidence || "Geen relevant config-blok gevonden.")}
                  {item.status === "manual" && (item.note || "Handmatig controleren.")}
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}
