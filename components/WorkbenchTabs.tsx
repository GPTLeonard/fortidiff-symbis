"use client";

import { useState } from "react";
import { ArrowLeftRight, FileSearch } from "lucide-react";
import { clsx } from "clsx";
import DiffWorkbench from "@/components/DiffWorkbench";
import SingleCheckWorkbench from "@/components/SingleCheckWorkbench";

type TabId = "diff" | "single";

export default function WorkbenchTabs() {
  const [active, setActive] = useState<TabId>("diff");

  const tabs: { id: TabId; label: string; icon: React.ComponentType<{ size?: number }> }[] = [
    { id: "diff", label: "Diff Workbench", icon: ArrowLeftRight },
    { id: "single", label: "Baseline Check", icon: FileSearch },
  ];

  return (
    <section className="space-y-6">
      <div className="flex flex-wrap gap-2 bg-[#0a0e05]/60 p-1.5 rounded-lg border border-[#94A807]/10">
        {tabs.map((tab) => (
          <button
            key={tab.id}
            onClick={() => setActive(tab.id)}
            className={clsx(
              "flex items-center gap-2 px-4 py-2 rounded-md text-xs font-medium transition-all duration-300",
              active === tab.id
                ? "bg-[#FFEB39] text-[#243305] shadow-[0_0_15px_rgba(255,235,57,0.15)]"
                : "text-[#a3a890] hover:text-[#fcfdec] hover:bg-[#243305]/50"
            )}
          >
            <tab.icon size={14} />
            {tab.label}
          </button>
        ))}
      </div>

      {active === "diff" ? <DiffWorkbench /> : <SingleCheckWorkbench />}
    </section>
  );
}
