import WorkbenchTabs from "@/components/WorkbenchTabs";
import { ShieldCheck, Cpu, Leaf } from "lucide-react";

export default function Home() {
  return (
    <main className="min-h-screen flex flex-col p-4 md:p-8 gap-8 max-w-[1800px] mx-auto">
      {/* Header */}
      <header className="flex flex-col md:flex-row md:items-center justify-between gap-6 border-b border-[#94A807]/10 pb-6">
        <div className="flex items-center gap-4">
          <div className="p-3 bg-[#243305] rounded-xl border border-[#94A807]/20 text-[#FFEB39] shadow-[0_0_15px_-3px_rgba(255,235,57,0.2)]">
            <ShieldCheck size={32} />
          </div>
          <div>
            <h1 className="text-2xl font-bold text-[#fcfdec] tracking-tight">
              FortiDiff <span className="text-[#FFEB39]">Symbis</span>
            </h1>
            <p className="text-[#a3a890] text-sm flex items-center gap-2">
              <span className="w-1.5 h-1.5 rounded-full bg-[#94A807]" />
              Secure Configuration Analysis
            </p>
          </div>
        </div>

        <div className="flex items-center gap-4">
          {/* Status indicators */}
          <div className="hidden md:flex items-center gap-2 px-3 py-1.5 rounded-full bg-[#4A5B0F]/10 border border-[#94A807]/20">
            <div className="w-2 h-2 rounded-full bg-[#94A807] animate-pulse shadow-[0_0_8px_#94A807]" />
            <span className="text-xs font-medium text-[#fcfdec]">Client-Side Secure</span>
          </div>
          <div className="flex items-center gap-2 px-3 py-1.5 rounded-full bg-[#243305] border border-[#94A807]/10">
            <Cpu size={14} className="text-[#a3a890]" />
            <span className="text-xs font-mono text-[#a3a890]">v1.5.1</span>
          </div>
        </div>
      </header>

      {/* Main Workbench */}
      <WorkbenchTabs />

      {/* Footer */}
      <footer className="mt-auto border-t border-[#94A807]/10 pt-6 flex justify-between items-center text-[#a3a890] text-xs font-mono">
        <div className="flex items-center gap-2">
          <Leaf size={12} className="text-[#4A5B0F]" />
          FortiDiff
        </div>
      </footer>
    </main>
  );
}
