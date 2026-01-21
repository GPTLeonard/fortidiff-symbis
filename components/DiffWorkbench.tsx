"use client";

import { useEffect, useMemo, useState } from "react";
import dynamic from "next/dynamic";
import FilePicker from "@/components/FilePicker";
import { type ExtractedDiff, extractDiff, optimizeDiffForAI } from "@/lib/diff";
import { type DetectedDate, detectConfigDate } from "@/lib/date";
import { copyToClipboard, downloadText } from "@/lib/download";
import { parseConfigHeader } from "@/lib/fortigate";
import { ArrowLeftRight, Copy, Download, FileJson, FileText, Split, Terminal } from "lucide-react";
import { clsx } from "clsx";

// Dynamically import Monaco Editor to avoid SSR issues
const DiffEditor = dynamic(
    async () => {
        const mod = await import("@monaco-editor/react");
        return mod.DiffEditor;
    },
    {
        ssr: false,
        loading: () => (
            <div className="h-[600px] w-full flex flex-col items-center justify-center bg-[#121a08] text-[#a3a890] gap-3 font-mono">
                <div className="w-8 h-8 border-2 border-[#243305] border-t-[#FFEB39] rounded-full animate-spin" />
                <span className="text-sm tracking-wider">LOADING ENVIRONMENT...</span>
            </div>
        )
    }
);

type FileState = { text: string; name: string; date: DetectedDate } | null;
const OUTPUT_TABS = [
    { id: "changes", label: "Contextual Changes", icon: FileText },
    { id: "unified", label: "Unified Diff", icon: Split },
    { id: "json", label: "JSON Structure", icon: FileJson },
] as const;

export default function DiffWorkbench() {
    const [oldFile, setOldFile] = useState<FileState>(null);
    const [newFile, setNewFile] = useState<FileState>(null);
    const [activeOutput, setActiveOutput] = useState<"changes" | "unified" | "json">("changes");
    const [copied, setCopied] = useState(false);
    const [aiOutput, setAiOutput] = useState<string>("");
    const [aiError, setAiError] = useState<string>("");
    const [aiLoading, setAiLoading] = useState(false);
    const oldHeader = useMemo(() => (oldFile ? parseConfigHeader(oldFile.text) : null), [oldFile]);
    const newHeader = useMemo(() => (newFile ? parseConfigHeader(newFile.text) : null), [newFile]);
    const passwordWarnings = useMemo(() => {
        const warnings: string[] = [];
        if (oldFile && oldHeader?.passwordMask !== true) {
            warnings.push(`Dude geen wachtwoorden erin (${oldFile.name})`);
        }
        if (newFile && newHeader?.passwordMask !== true) {
            warnings.push(`Dude geen wachtwoorden erin (${newFile.name})`);
        }
        return warnings;
    }, [oldFile, oldHeader, newFile, newHeader]);

    // Auto-swap logic
    useEffect(() => {
        if (oldFile?.date.time && newFile?.date.time) {
            if (oldFile.date.time > newFile.date.time) {
                setOldFile(newFile);
                setNewFile(oldFile);
            }
        }
    }, [oldFile, newFile]);

    // Async Diff Calculation to prevent blocking main thread (INP optimization)
    const [isComputing, setIsComputing] = useState(false);
    const [extracted, setExtracted] = useState<ExtractedDiff | null>(null);

    useEffect(() => {
        if (!oldFile || !newFile) {
            setExtracted(null);
            return;
        }

        setIsComputing(true);

        // Short timeout to allow UI to render "Computing..." state before heavy lifting
        const timer = setTimeout(() => {
            // In a real heavy-duty scenario, this would be a Web Worker.
            // For now, deferred execution prevents UI freeze on input change.
            const result = extractDiff(oldFile.text, newFile.text);
            setExtracted(result);
            setIsComputing(false);
        }, 50);

        return () => clearTimeout(timer);
    }, [oldFile, newFile]);

    const handleCopy = async () => {
        if (!extracted) return;
        let text = "";
        if (activeOutput === "changes") text = extracted.contextualDiff;
        else if (activeOutput === "unified") text = extracted.unifiedDiff;
        else text = JSON.stringify(extracted.hunksJson, null, 2);

        await copyToClipboard(text);
        setCopied(true);
        setTimeout(() => setCopied(false), 2000);
    };

    const handleDownload = () => {
        if (!extracted) return;
        let text = "";
        let ext = "txt";
        if (activeOutput === "changes") { text = extracted.contextualDiff; ext = "txt"; }
        else if (activeOutput === "unified") { text = extracted.unifiedDiff; ext = "diff"; }
        else { text = JSON.stringify(extracted.hunksJson, null, 2); ext = "json"; }

        downloadText(`fortidiff-changes.${ext}`, text);
    };

    const handleFile = (side: "left" | "right", text: string, name: string) => {
        const date = detectConfigDate(text, name);
        const fileState = { text, name, date };
        if (side === "left") setOldFile(fileState);
        else setNewFile(fileState);
    };

    const buildPrompt = (diffContent: string) => `ROL
Je bent een senior netwerk- en security engineer gespecialiseerd in Fortinet FortiGate configuraties.
Je schrijft professionele changelogs voor CAB en operations.

TAAK
Analyseer het aangeleverde configuratieverschil en produceer een duidelijke, feitelijke changelog.
Gebruik uitsluitend informatie uit de input. Verzin niets.

INPUT
De input bevat config-headers en alleen gewijzigde edit-blokken.
Wijzigingen zijn gemarkeerd met "+" of "-"; ongewijzigde contextregels beginnen met twee spaties.

REGELS
- Baseer conclusies op expliciete wijzigingen (+ of -). Gebruik contextregels alleen om de wijziging te duiden.
- Behandel ongewijzigde contextregels nooit als een wijziging.
- Groepeer logisch (bijvoorbeeld: Interfaces, VPN, Policies, System, Scripts, Certificates).
- Benoem ENC values, passwords en certificaten alleen als "gewijzigd", nooit inhoud tonen.
- Negeer of markeer ruis (timestamps, conf_file_ver, auto-backups) expliciet als niet-functioneel.
- Geef alleen impact als deze logisch volgt uit de wijziging.
- Schrijf in helder, zakelijk Nederlands.

OUTPUTSTRUCTUUR
1. Overzicht (maximaal 5 bullets)
2. Wijzigingen per onderdeel (bullets per categorie)
3. Impact en risico’s (alleen indien relevant)
4. Onzekerheden of aannames (optioneel)
5. Korte samenvatting (1 alinea, geschikt als release note)

CONFIGURATIEVERSCHIL
${diffContent}`;

    const handleSymGPT = async () => {
        if (!extracted) return;

        // Optimized for AI: Truncate secrets and heavy blobs
        const optimizedDiff = optimizeDiffForAI(extracted.contextualDiff);

        // URL safety limit (User requested exactly 10,000 chars)
        const MAX_URL_LENGTH = 10000;

        // 1. Try Full Prompt
        const finalPrompt = buildPrompt(optimizedDiff);
        const encoded = encodeURIComponent(finalPrompt);

        if (encoded.length <= MAX_URL_LENGTH) {
            const url = `https://chat.symbis.ai/c/new?prompt=${encoded}&submit=true`;
            window.open(url, "_blank");
        } else {
            // Fallback for larger payloads (Auto-copy)
            await copyToClipboard(finalPrompt);
            const placeholder = `[SYSTEM: De configuratie-diff was te groot voor de URL (>10k chars). De volledige prompt (inclusief data) is naar je klembord gekopieerd. PLAK HIERONDER om te starten.]`;
            const url = `https://chat.symbis.ai/c/new?prompt=${encodeURIComponent(placeholder)}&submit=false`;
            window.open(url, "_blank");
            setCopied(true);
            setTimeout(() => setCopied(false), 2000);
        }
    };

    const handleAzureGPT = async () => {
        if (!extracted) return;

        setAiError("");
        setAiOutput("");
        setAiLoading(true);

        try {
            const optimizedDiff = optimizeDiffForAI(extracted.contextualDiff);
            const finalPrompt = buildPrompt(optimizedDiff);

            const res = await fetch("/api/chat", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ prompt: finalPrompt })
            });

            if (!res.ok) {
                const errorText = await res.text();
                throw new Error(errorText || "AI request failed.");
            }

            const data = await res.json();
            setAiOutput(String(data.text || ""));
        } catch (err) {
            const message = err instanceof Error ? err.message : "Unexpected error.";
            setAiError(message);
        } finally {
            setAiLoading(false);
        }
    };

    return (
        <div className="w-full space-y-6 animate-in fade-in duration-500">
            {/* File Pickers */}
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
                <FilePicker
                    label="Old Configuration"
                    hint="Reference Baseline"
                    filename={oldFile?.name ?? null}
                    detectedIso={oldFile?.date.iso ?? null}
                    detectedSource={oldFile?.date.source ?? null}
                    onText={(text, name) => handleFile("left", text, name)}
                />
                <FilePicker
                    label="New Configuration"
                    hint="Target State"
                    filename={newFile?.name ?? null}
                    detectedIso={newFile?.date.iso ?? null}
                    detectedSource={newFile?.date.source ?? null}
                    onText={(text, name) => handleFile("right", text, name)}
                />
            </div>
            {passwordWarnings.length > 0 && (
                <div className="rounded-xl border border-[#FFB347]/30 bg-[#2a1208]/50 px-4 py-3 text-xs text-[#FFB347] space-y-1">
                    {passwordWarnings.map((warning) => (
                        <div key={warning}>{warning}</div>
                    ))}
                </div>
            )}

            {/* Editor Container */}
            <div className="bg-[#121a08]/80 border border-[#94A807]/20 backdrop-blur-xl shadow-2xl rounded-xl overflow-hidden flex flex-col h-[700px]">
                {/* Editor Toolbar */}
                <div className="h-12 border-b border-[#94A807]/10 bg-[#243305]/30 flex items-center px-4 justify-between">
                    <div className="flex items-center gap-2 text-xs font-mono text-[#94A807]/80">
                        <Terminal size={14} />
                        <span className="tracking-widest">DIFF_VIEWER_Active</span>
                        {isComputing && <span className="text-[#FFEB39] animate-pulse ml-2">COMPUTING...</span>}
                    </div>
                    {extracted && !isComputing && (
                        <div className="flex items-center gap-3">
                            <span className="flex items-center gap-1.5 text-xs text-red-300 bg-red-900/20 px-2 py-0.5 rounded border border-red-900/30">
                                -{extracted.stats.removed}
                            </span>
                            <span className="flex items-center gap-1.5 text-xs text-[#FFEB39] bg-[#FFEB39]/10 px-2 py-0.5 rounded border border-[#FFEB39]/20">
                                +{extracted.stats.added}
                            </span>
                        </div>
                    )}
                </div>

                <div className="flex-1 relative bg-[#0e1206]">
                    {/* Note: In dark mode, monaco vs-dark is good, but we might want a custom theme later. 
              Keeping vs-dark for stability but ensuring container matches symbis vibe. */}
                    {oldFile && newFile ? (
                        <DiffEditor
                            original={oldFile.text}
                            modified={newFile.text}
                            language="ini"
                            theme="vs-dark"
                            options={{
                                renderSideBySide: true,
                                readOnly: true,
                                scrollBeyondLastLine: false,
                                fontSize: 13,
                                fontFamily: "'JetBrains Mono', 'Fira Code', Consolas, monospace",
                                lineHeight: 20,
                                padding: { top: 16, bottom: 16 },
                                originalEditable: false,
                                diffWordWrap: "off",
                                renderOverviewRuler: true,
                                overviewRulerBorder: false,
                                minimap: {
                                    enabled: true,
                                    scale: 0.8,
                                    showSlider: "always", // Visual cue for scrolling
                                },
                            }}
                        />
                    ) : (
                        <div className="absolute inset-0 flex flex-col items-center justify-center text-[#a3a890] space-y-4">
                            <div className="p-4 rounded-full bg-[#243305]/40 border border-[#94A807]/10">
                                <ArrowLeftRight size={32} className="text-[#94A807]" />
                            </div>
                            <p className="font-light tracking-wide">Upload configurations to initialize comparison</p>
                        </div>
                    )}
                </div>
            </div>

            {/* Logic Extraction Panel */}
            {extracted && (
                <div className="bg-[#121a08]/80 border border-[#94A807]/20 backdrop-blur-xl shadow-2xl rounded-xl p-6 space-y-6 font-sans">
                    <div className="flex flex-col md:flex-row md:items-center justify-between gap-6">
                        <div>
                            <h3 className="text-lg font-semibold text-[#fcfdec]">AI Context Export</h3>
                            <p className="text-sm text-[#a3a890] mt-1">
                                Optimized output payload for LLM analysis
                            </p>
                        </div>

                        <div className="flex gap-2 bg-[#0a0e05]/60 p-1.5 rounded-lg border border-[#94A807]/10">
                            {OUTPUT_TABS.map((tab) => (
                                <button
                                    key={tab.id}
                                    onClick={() => setActiveOutput(tab.id)}
                                    className={clsx(
                                        "flex items-center gap-2 px-3 py-1.5 rounded-md text-xs font-medium transition-all duration-300",
                                        activeOutput === tab.id
                                            ? "bg-[#FFEB39] text-[#243305] shadow-[0_0_15px_rgba(255,235,57,0.15)]"
                                            : "text-[#a3a890] hover:text-[#fcfdec] hover:bg-[#243305]/50"
                                    )}
                                >
                                    <tab.icon size={14} />
                                    {tab.label}
                                </button>
                            ))}
                        </div>
                    </div>

                    <div className="relative group">
                        {/* Ambient glow */}
                        <div className="absolute -inset-[1px] bg-gradient-to-r from-[#94A807]/20 to-[#4A5B0F]/20 rounded-xl opacity-0 group-hover:opacity-100 transition duration-700 -z-10 blur-md" />

                        <div className="relative rounded-xl border border-[#94A807]/10 bg-[#0a0e05] overflow-hidden">
                            <div className="absolute top-0 right-0 p-4 flex gap-2 opacity-0 group-hover:opacity-100 transition-opacity z-10">
                                <button
                                    onClick={handleCopy}
                                    className="bg-[#243305] border border-[#94A807]/30 hover:bg-[#FFEB39] hover:text-[#243305] text-[#94A807] transition-all duration-200 p-2 rounded-lg flex items-center gap-2 text-xs font-medium shadow-lg"
                                >
                                    {copied ? <span className="font-bold">Copied!</span> : <>
                                        <Copy size={14} />
                                        <span>Copy</span>
                                    </>}
                                </button>
                                <button
                                    onClick={handleDownload}
                                    className="bg-[#243305] border border-[#94A807]/30 hover:bg-[#FFEB39] hover:text-[#243305] text-[#94A807] transition-all duration-200 p-2 rounded-lg shadow-lg"
                                >
                                    <Download size={14} />
                                </button>
                            </div>

                            <textarea
                                className="w-full h-80 bg-transparent text-[#d1d5db] font-mono text-sm p-5 resize-y focus:outline-none"
                                readOnly
                                value={
                                    activeOutput === "changes"
                                        ? extracted.contextualDiff
                                        : activeOutput === "unified"
                                            ? extracted.unifiedDiff
                                            : JSON.stringify(extracted.hunksJson, null, 2)
                                }
                                spellCheck={false}
                            />
                        </div>

                        {/* SymGPT Integration */}
                        <div className="flex flex-wrap justify-end gap-3">
                            <button
                                onClick={handleSymGPT}
                                className="bg-[#FFEB39] hover:bg-[#ffe600] text-[#243305] px-6 py-3 rounded-xl font-bold flex items-center gap-3 shadow-[0_0_20px_rgba(255,235,57,0.3)] hover:shadow-[0_0_30px_rgba(255,235,57,0.5)] transition-all transform hover:scale-[1.02] active:scale-[0.98]"
                            >
                                <svg width="20" height="20" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg" className="text-[#243305]">
                                    <path d="M12 2L2 7L12 12L22 7L12 2Z" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" />
                                    <path d="M2 17L12 22L22 17" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" />
                                    <path d="M2 12L12 17L22 12" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" />
                                </svg>
                                Analyze with SymGPT
                            </button>
                            <button
                                onClick={handleAzureGPT}
                                className="bg-[#0f1a07] hover:bg-[#1a2b0a] text-[#FFEB39] px-6 py-3 rounded-xl font-bold flex items-center gap-3 border border-[#FFEB39]/30 shadow-[0_0_20px_rgba(148,168,7,0.2)] hover:shadow-[0_0_30px_rgba(148,168,7,0.35)] transition-all transform hover:scale-[1.02] active:scale-[0.98]"
                            >
                                <span className="text-xs tracking-widest">GPT-4.1</span>
                                {aiLoading ? "Analyzing..." : "Analyze Internally"}
                            </button>
                        </div>
                    </div>

                    <div className="relative rounded-xl border border-[#94A807]/10 bg-[#0a0e05] overflow-hidden">
                        <div className="px-5 py-3 border-b border-[#94A807]/10 flex items-center justify-between">
                            <span className="text-xs uppercase tracking-[0.2em] text-[#94A807]/80">Internal Analysis Output</span>
                            {aiError && <span className="text-xs text-red-300">{aiError}</span>}
                        </div>
                        <textarea
                            className="w-full h-56 bg-transparent text-[#d1d5db] font-mono text-sm p-5 resize-y focus:outline-none"
                            readOnly
                            value={aiOutput || (aiLoading ? "Analyzing with GPT-4.1..." : "No internal analysis yet.")}
                            spellCheck={false}
                        />
                    </div>
                </div>
            )}
        </div>
    );
}
