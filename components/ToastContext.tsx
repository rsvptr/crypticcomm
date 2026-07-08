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

const TOAST_ICONS: Record<ToastVariant, { icon: typeof CheckCircle2; className: string }> = {
  success: { icon: CheckCircle2, className: "text-emerald-400" },
  error: { icon: AlertCircle, className: "text-rose-400" },
  info: { icon: Info, className: "text-indigo-300" },
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
      <div
        aria-live="polite"
        className="pointer-events-none fixed inset-x-4 bottom-4 z-[110] flex flex-col items-center gap-2 sm:inset-x-auto sm:right-5 sm:bottom-5 sm:items-end"
      >
        <AnimatePresence initial={false}>
          {toasts.map((toast) => {
            const tone = TOAST_ICONS[toast.variant];
            const Icon = tone.icon;

            return (
              <motion.div
                key={toast.id}
                initial={{ opacity: 0, y: 12, scale: 0.98 }}
                animate={{ opacity: 1, y: 0, scale: 1 }}
                exit={{ opacity: 0, y: 8, scale: 0.98 }}
                transition={{ duration: 0.18, ease: "easeOut" }}
                className="pointer-events-auto w-full max-w-sm rounded-lg border border-white/10 bg-surface-raised shadow-lg shadow-black/40"
              >
                <div className="flex items-start gap-2.5 px-3.5 py-3">
                  <Icon className={`mt-0.5 h-4 w-4 shrink-0 ${tone.className}`} />
                  <div className="min-w-0 flex-1">
                    <p className="text-sm font-medium text-zinc-100">{toast.title}</p>
                    {toast.description && (
                      <p className="mt-0.5 text-[13px] leading-5 text-zinc-400">
                        {toast.description}
                      </p>
                    )}
                  </div>
                  <button
                    type="button"
                    onClick={() => dismiss(toast.id)}
                    className="rounded-md p-1 text-zinc-500 transition-colors duration-150 hover:bg-white/[0.06] hover:text-zinc-200"
                    aria-label="Dismiss notification"
                  >
                    <X className="h-3.5 w-3.5" />
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
