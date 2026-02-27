"use client";

import { motion } from "framer-motion";
import clsx from "clsx";
import { ReactNode, useRef } from "react";
import { Upload } from "lucide-react";

export function Card({ children, className }: { children: ReactNode; className?: string }) {
  return (
    <motion.div
      initial={{ opacity: 0, y: 10 }}
      animate={{ opacity: 1, y: 0 }}
      className={clsx(
        "bg-slate-900/60 backdrop-blur-md border border-slate-800 rounded-xl p-6 shadow-xl",
        className
      )}
    >
      {children}
    </motion.div>
  );
}

export function NeonButton({
  children,
  onClick,
  disabled,
  className,
  variant = "primary",
  type = "button",
}: {
  children: ReactNode;
  onClick?: () => void;
  disabled?: boolean;
  className?: string;
  variant?: "primary" | "secondary" | "danger" | "ghost";
  type?: "button" | "submit" | "reset";
}) {
  const baseStyles = "px-6 py-2.5 rounded-lg font-medium transition-all duration-200 flex items-center justify-center gap-2 disabled:opacity-50 disabled:cursor-not-allowed active:scale-95 select-none";
  
  const variants = {
    primary: "bg-indigo-600 hover:bg-indigo-500 text-white shadow-[0_0_15px_rgba(79,70,229,0.3)] hover:shadow-[0_0_25px_rgba(79,70,229,0.5)]",
    secondary: "bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 hover:border-slate-600",
    danger: "bg-red-500/10 hover:bg-red-500/20 text-red-400 border border-red-500/20",
    ghost: "bg-transparent hover:bg-slate-800/50 text-slate-400 hover:text-slate-200"
  };

  return (
    <motion.button
      type={type}
      whileTap={{ scale: 0.98 }}
      onClick={onClick}
      disabled={disabled}
      className={clsx(baseStyles, variants[variant], className)}
    >
      {children}
    </motion.button>
  );
}

export function FadeIn({ children, delay = 0, className }: { children: ReactNode; delay?: number; className?: string }) {
  return (
    <motion.div
      initial={{ opacity: 0, y: 10 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ delay, duration: 0.4 }}
      className={className}
    >
      {children}
    </motion.div>
  );
}

export function FileUpload({ 
  onFileSelect, 
  accept = ".json", 
  label = "Upload File" 
}: { 
  onFileSelect: (content: string) => void; 
  accept?: string;
  label?: string;
}) {
  const inputRef = useRef<HTMLInputElement>(null);

  const handleChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (file) {
      const reader = new FileReader();
      reader.onload = (ev) => {
        if (ev.target?.result) {
          onFileSelect(ev.target.result as string);
        }
      };
      reader.readAsText(file);
    }
    // Reset value so same file can be selected again if needed
    if (inputRef.current) inputRef.current.value = "";
  };

  return (
    <>
      <input
        type="file"
        ref={inputRef}
        accept={accept}
        onChange={handleChange}
        className="hidden"
      />
      <button
        onClick={() => inputRef.current?.click()}
        className="text-xs flex items-center gap-1 text-slate-400 hover:text-indigo-400 transition-colors"
      >
        <Upload className="w-3 h-3" /> {label}
      </button>
    </>
  );
}
