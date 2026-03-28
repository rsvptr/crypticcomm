"use client";

import {
  createContext,
  ReactNode,
  useCallback,
  useContext,
  useMemo,
  useState,
} from "react";
import { AnimatePresence, motion } from "framer-motion";
import { AlertCircle, CheckCircle2, Info, X } from "lucide-react";
import clsx from "clsx";

type ToastVariant = "success" | "error" | "info";

interface Toast {
  id: string;
  title: string;
  description?: string;
  variant: ToastVariant;
}

interface ToastInput {
  title: string;
  description?: string;
}

interface ToastContextValue {
  pushToast: (toast: ToastInput & { variant?: ToastVariant }) => void;
  success: (toast: ToastInput) => void;
  error: (toast: ToastInput) => void;
  info: (toast: ToastInput) => void;
}

const ToastContext = createContext<ToastContextValue | undefined>(undefined);

const TOAST_STYLES: Record<
  ToastVariant,
  { icon: typeof CheckCircle2; classes: string }
> = {
  success: {
    icon: CheckCircle2,
    classes:
      "border-emerald-500/30 bg-emerald-500/10 text-emerald-50 shadow-[0_18px_60px_rgba(16,185,129,0.18)]",
  },
  error: {
    icon: AlertCircle,
    classes:
      "border-rose-500/30 bg-rose-500/10 text-rose-50 shadow-[0_18px_60px_rgba(244,63,94,0.2)]",
  },
  info: {
    icon: Info,
    classes:
      "border-cyan-500/30 bg-cyan-500/10 text-cyan-50 shadow-[0_18px_60px_rgba(34,211,238,0.18)]",
  },
};

export function ToastProvider({ children }: { children: ReactNode }) {
  const [toasts, setToasts] = useState<Toast[]>([]);

  const dismiss = useCallback((id: string) => {
    setToasts((current) => current.filter((toast) => toast.id !== id));
  }, []);

  const pushToast = useCallback(
    ({ title, description, variant = "info" }: ToastInput & { variant?: ToastVariant }) => {
      const id = crypto.randomUUID();
      const toast: Toast = { id, title, description, variant };
      setToasts((current) => [...current, toast].slice(-4));
      window.setTimeout(() => dismiss(id), 4200);
    },
    [dismiss]
  );

  const value = useMemo<ToastContextValue>(
    () => ({
      pushToast,
      success: (toast) => pushToast({ ...toast, variant: "success" }),
      error: (toast) => pushToast({ ...toast, variant: "error" }),
      info: (toast) => pushToast({ ...toast, variant: "info" }),
    }),
    [pushToast]
  );

  return (
    <ToastContext.Provider value={value}>
      {children}
      <div className="pointer-events-none fixed right-4 top-20 z-[120] flex w-full max-w-sm flex-col gap-3 sm:right-6">
        <AnimatePresence initial={false}>
          {toasts.map((toast) => {
            const tone = TOAST_STYLES[toast.variant];
            const Icon = tone.icon;

            return (
              <motion.div
                key={toast.id}
                initial={{ opacity: 0, y: 12, scale: 0.96 }}
                animate={{ opacity: 1, y: 0, scale: 1 }}
                exit={{ opacity: 0, y: -10, scale: 0.98 }}
                transition={{ duration: 0.2, ease: "easeOut" }}
                className={clsx(
                  "pointer-events-auto overflow-hidden rounded-2xl border backdrop-blur-xl",
                  tone.classes
                )}
              >
                <div className="flex items-start gap-3 p-4">
                  <div className="mt-0.5 rounded-full border border-white/10 bg-white/10 p-2">
                    <Icon className="h-4 w-4" />
                  </div>
                  <div className="min-w-0 flex-1">
                    <p className="text-sm font-semibold tracking-tight">{toast.title}</p>
                    {toast.description && (
                      <p className="mt-1 text-sm text-white/70">{toast.description}</p>
                    )}
                  </div>
                  <button
                    type="button"
                    onClick={() => dismiss(toast.id)}
                    className="rounded-full p-1 text-white/60 transition hover:bg-white/10 hover:text-white"
                    aria-label="Dismiss notification"
                  >
                    <X className="h-4 w-4" />
                  </button>
                </div>
              </motion.div>
            );
          })}
        </AnimatePresence>
      </div>
    </ToastContext.Provider>
  );
}

export function useToast() {
  const context = useContext(ToastContext);
  if (!context) {
    throw new Error("useToast must be used within a ToastProvider");
  }
  return context;
}
