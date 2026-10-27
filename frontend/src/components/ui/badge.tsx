import { HTMLAttributes } from "react";

import { cn } from "@/lib/utils";

type Tone = "neutral" | "ok" | "warn" | "danger" | "info" | "ai";

const tones: Record<Tone, string> = {
  neutral: "bg-slate-800 text-slate-300 border-slate-700",
  ok: "bg-emerald-900/50 text-emerald-300 border-emerald-700/60",
  warn: "bg-amber-900/50 text-amber-300 border-amber-700/60",
  danger: "bg-red-900/50 text-red-300 border-red-700/60",
  info: "bg-sky-900/50 text-sky-300 border-sky-700/60",
  ai: "bg-violet-900/40 text-violet-300 border-violet-700/60",
};

export function Badge({
  tone = "neutral",
  className,
  ...props
}: HTMLAttributes<HTMLSpanElement> & { tone?: Tone }) {
  return (
    <span
      className={cn(
        "inline-flex items-center gap-1 rounded-full border px-2 py-0.5 text-xs font-medium whitespace-nowrap",
        tones[tone],
        className,
      )}
      {...props}
    />
  );
}
