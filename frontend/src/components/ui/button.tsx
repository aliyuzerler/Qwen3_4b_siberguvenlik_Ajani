import { ButtonHTMLAttributes } from "react";

import { cn } from "@/lib/utils";

type Variant = "default" | "outline" | "ghost" | "danger";

const variants: Record<Variant, string> = {
  default:
    "bg-sky-600 text-white hover:bg-sky-500 disabled:bg-sky-900 disabled:text-slate-400",
  outline:
    "border border-slate-700 bg-transparent text-slate-200 hover:bg-slate-800",
  ghost: "bg-transparent text-slate-300 hover:bg-slate-800",
  danger: "bg-red-700/80 text-white hover:bg-red-600",
};

export function Button({
  className,
  variant = "default",
  ...props
}: ButtonHTMLAttributes<HTMLButtonElement> & { variant?: Variant }) {
  return (
    <button
      className={cn(
        "inline-flex items-center justify-center gap-2 rounded-md px-3 py-1.5 text-sm font-medium transition-colors disabled:cursor-not-allowed disabled:opacity-70",
        variants[variant],
        className,
      )}
      {...props}
    />
  );
}
