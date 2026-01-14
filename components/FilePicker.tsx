"use client";

import { useId, useMemo } from "react";
import { Upload, CheckCircle2, Calendar, FileType } from "lucide-react";
import { clsx } from "clsx";

type Props = {
    label: string;
    hint: string;
    filename: string | null;
    detectedIso: string | null;
    detectedSource: string | null;
    onText: (text: string, filename: string) => void;
};

export default function FilePicker({
    label,
    hint,
    filename,
    detectedIso,
    detectedSource,
    onText,
}: Props) {
    const id = useId();
    const hasFile = !!filename;
    const extension = useMemo(() => {
        if (!filename) return "CONF";
        const parts = filename.split(".");
        const last = parts[parts.length - 1] || "conf";
        return last.toUpperCase();
    }, [filename]);

    async function onFileChange(e: React.ChangeEvent<HTMLInputElement>) {
        const f = e.target.files?.[0];
        if (!f) return;

        // Security Hardening: Max 10MB limit (Client-Side DoS Prevention)
        const MAX_SIZE = 10 * 1024 * 1024; // 10MB
        if (f.size > MAX_SIZE) {
            alert(`Het bestand "${f.name}" is te groot (${(f.size / 1024 / 1024).toFixed(1)}MB). Maximale grootte is 10MB om browser crashes te voorkomen.`);
            e.target.value = "";
            return;
        }

        const text = await f.text();
        onText(text, f.name);
        e.target.value = "";
    }

    return (
        <div className={clsx(
            "relative group transition-all duration-300",
            "rounded-xl border border-dashed p-6",
            hasFile
                ? "border-[#94A807]/40 bg-[#243305]/20 shadow-[0_0_30px_-5px_rgba(74,91,15,0.3)]"
                : "border-[#94A807]/10 hover:border-[#FFEB39]/40 bg-[#121a08]/50 hover:bg-[#243305]/30"
        )}>
            <input
                id={id}
                type="file"
                accept=".conf,.txt,.yaml,.yml"
                onChange={onFileChange}
                className="absolute inset-0 w-full h-full opacity-0 cursor-pointer z-10"
            />

            <div className="flex flex-col items-center justify-center text-center gap-3">
                {/* Icon State */}
                <div className={clsx(
                    "p-3 rounded-full transition-all duration-300",
                    hasFile
                        ? "bg-[#FFEB39] text-[#243305] shadow-lg shadow-[#FFEB39]/20 scale-110"
                        : "bg-[#243305] text-[#94A807] group-hover:text-[#FFEB39] group-hover:scale-110"
                )}>
                    {hasFile ? <CheckCircle2 size={24} /> : <Upload size={24} />}
                </div>

                {/* Text Content */}
                <div className="space-y-1">
                    <h3 className={clsx("font-medium transition-colors", hasFile ? "text-[#FFEB39]" : "text-[#fcfdec]")}>
                        {hasFile ? filename : label}
                    </h3>
                    <p className="text-xs text-[#a3a890] max-w-[200px] mx-auto group-hover:text-[#fcfdec]/80 transition-colors">
                        {hasFile ? "Klik of sleep om te vervangen" : hint}
                    </p>
                </div>

                {/* Metadata Badges */}
                {hasFile && (
                    <div className="flex flex-wrap gap-2 mt-2 justify-center">
                        <div className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-md bg-[#0a0e05] border border-[#94A807]/20 text-xs text-[#94A807] font-mono shadow-sm">
                            <FileType size={12} />
                            {extension}
                        </div>
                        {detectedIso && (
                            <div className={clsx(
                                "inline-flex items-center gap-1.5 px-2.5 py-1 rounded-md border text-xs font-mono transition-colors shadow-sm",
                                detectedIso
                                    ? "bg-[#4A5B0F]/20 border-[#94A807]/30 text-[#fcfdec]"
                                    : "bg-white/5 border-white/5 text-white/40"
                            )}>
                                <Calendar size={12} className="text-[#FFEB39]" />
                                {detectedIso}
                            </div>
                        )}
                        {detectedSource && (
                            <div className="inline-flex items-center px-2.5 py-1 rounded-md bg-[#0a0e05] border border-[#94A807]/10 text-[10px] uppercase tracking-[0.2em] text-[#a3a890]">
                                {detectedSource === "content" ? "Inhoud" : "Bestandsnaam"}
                            </div>
                        )}
                    </div>
                )}
            </div>
        </div>
    );
}
