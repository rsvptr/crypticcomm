"use client";

import { ChangeEvent, ReactNode, useRef } from "react";
import { HTMLMotionProps, motion } from "framer-motion";
import clsx from "clsx";
import { Upload } from "lucide-react";

export function Card({
  children,
  className,
  ...props
}: HTMLMotionProps<"section"> & {
  children: ReactNode;
}) {
  return (
    <motion.section
      initial={{ opacity: 0, y: 12 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.35, ease: "easeOut" }}
      className={clsx("panel", className)}
      {...props}
    >
      {children}
    </motion.section>
  );
}

type ButtonVariant = "primary" | "secondary" | "danger" | "ghost";
type ButtonSize = "sm" | "md" | "lg" | "icon";

const BUTTON_VARIANTS: Record<ButtonVariant, string> = {
  primary:
    "bg-[linear-gradient(135deg,rgba(67,97,238,1),rgba(88,28,135,0.95))] text-white shadow-[0_16px_45px_rgba(67,97,238,0.28)] hover:shadow-[0_18px_52px_rgba(88,28,135,0.34)] hover:brightness-110",
  secondary:
    "border border-white/10 bg-white/5 text-slate-100 hover:bg-white/10 hover:text-white",
  danger:
    "border border-rose-500/30 bg-rose-500/10 text-rose-100 hover:bg-rose-500/20",
  ghost:
    "bg-transparent text-slate-300 hover:bg-white/5 hover:text-white",
};

const BUTTON_SIZES: Record<ButtonSize, string> = {
  sm: "min-h-[40px] rounded-xl px-3.5 py-2 text-sm",
  md: "min-h-[48px] rounded-2xl px-5 py-3 text-sm",
  lg: "min-h-[56px] rounded-2xl px-6 py-3.5 text-base",
  icon: "h-12 w-12 rounded-2xl p-0",
};

export function NeonButton({
  children,
  className,
  variant = "primary",
  size = "md",
  type = "button",
  ...props
}: HTMLMotionProps<"button"> & {
  children: ReactNode;
  variant?: ButtonVariant;
  size?: ButtonSize;
}) {
  return (
    <motion.button
      type={type}
      whileTap={{ scale: props.disabled ? 1 : 0.98 }}
      className={clsx(
        "inline-flex items-center justify-center gap-2 font-semibold tracking-tight transition duration-200 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-cyan-300/80 focus-visible:ring-offset-2 focus-visible:ring-offset-[#060816] disabled:cursor-not-allowed disabled:opacity-50",
        BUTTON_VARIANTS[variant],
        BUTTON_SIZES[size],
        className
      )}
      {...props}
    >
      {children}
    </motion.button>
  );
}

export function FadeIn({
  children,
  delay = 0,
  className,
}: {
  children: ReactNode;
  delay?: number;
  className?: string;
}) {
  return (
    <motion.div
      initial={{ opacity: 0, y: 14 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ delay, duration: 0.4, ease: "easeOut" }}
      className={className}
    >
      {children}
    </motion.div>
  );
}

export function FileUpload({
  onFileSelect,
  accept = ".json",
  label = "Upload File",
  className,
}: {
  onFileSelect: (content: string) => void;
  accept?: string;
  label?: string;
  className?: string;
}) {
  const inputRef = useRef<HTMLInputElement>(null);

  const handleChange = (event: ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0];
    if (!file) {
      return;
    }

    const reader = new FileReader();
    reader.onload = (loadEvent) => {
      if (typeof loadEvent.target?.result === "string") {
        onFileSelect(loadEvent.target.result);
      }
    };
    reader.readAsText(file);

    if (inputRef.current) {
      inputRef.current.value = "";
    }
  };

  return (
    <>
      <input
        ref={inputRef}
        type="file"
        accept={accept}
        onChange={handleChange}
        className="hidden"
      />
      <button
        type="button"
        onClick={() => inputRef.current?.click()}
        className={clsx(
          "inline-flex min-h-[40px] items-center gap-1.5 rounded-full border border-white/10 bg-white/5 px-3 py-2 text-xs font-medium text-slate-300 transition hover:border-cyan-400/30 hover:bg-cyan-400/10 hover:text-cyan-100",
          className
        )}
      >
        <Upload className="h-3.5 w-3.5" />
        {label}
      </button>
    </>
  );
}
