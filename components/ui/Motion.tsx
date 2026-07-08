"use client";

import {
  ButtonHTMLAttributes,
  ChangeEvent,
  ReactNode,
  useRef,
} from "react";
import { AnimatePresence, motion, Variants } from "framer-motion";
import clsx, { ClassValue } from "clsx";
import { twMerge } from "tailwind-merge";
import { Upload } from "lucide-react";

/** Class combiner: clsx for conditionals, tailwind-merge so caller-supplied
    utilities reliably override component defaults. */
function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

/* Shared primitives for the whole app. Radius scale: cards rounded-xl,
   controls rounded-lg, chips rounded-md (documented in globals.css). */

export function Card({
  children,
  className,
  ...props
}: React.HTMLAttributes<HTMLElement> & {
  children: ReactNode;
}) {
  return (
    <section className={clsx("panel", className)} {...props}>
      {children}
    </section>
  );
}

export function CardHeader({
  title,
  description,
  actions,
}: {
  title: ReactNode;
  description?: ReactNode;
  actions?: ReactNode;
}) {
  return (
    <div className="flex flex-wrap items-start justify-between gap-x-4 gap-y-2 border-b border-white/[0.06] px-4 py-3.5 sm:px-5">
      <div className="min-w-0">
        <h3 className="text-[15px] font-semibold tracking-tight text-zinc-100">{title}</h3>
        {description && (
          <p className="mt-0.5 text-[13px] leading-5 text-zinc-500">{description}</p>
        )}
      </div>
      {actions && <div className="flex shrink-0 items-center gap-1.5">{actions}</div>}
    </div>
  );
}

export function CardBody({
  children,
  className,
}: {
  children: ReactNode;
  className?: string;
}) {
  return <div className={clsx("px-4 py-4 sm:px-5", className)}>{children}</div>;
}

type ButtonVariant = "primary" | "secondary" | "danger" | "ghost";
type ButtonSize = "sm" | "md" | "lg" | "icon";

const BUTTON_VARIANTS: Record<ButtonVariant, string> = {
  primary:
    "bg-indigo-600 text-white hover:bg-indigo-500 disabled:hover:bg-indigo-600",
  secondary:
    "border border-white/10 bg-white/[0.04] text-zinc-200 hover:border-white/20 hover:bg-white/[0.08] hover:text-white",
  danger:
    "border border-rose-500/30 bg-rose-500/10 text-rose-200 hover:bg-rose-500/20",
  ghost: "text-zinc-400 hover:bg-white/[0.06] hover:text-zinc-100",
};

const BUTTON_SIZES: Record<ButtonSize, string> = {
  sm: "h-8 gap-1.5 rounded-lg px-3 text-[13px]",
  md: "h-10 gap-2 rounded-lg px-4 text-sm",
  lg: "h-11 gap-2 rounded-lg px-5 text-sm",
  icon: "h-8 w-8 rounded-lg",
};

export function Button({
  children,
  className,
  variant = "primary",
  size = "md",
  type = "button",
  ...props
}: ButtonHTMLAttributes<HTMLButtonElement> & {
  children: ReactNode;
  variant?: ButtonVariant;
  size?: ButtonSize;
}) {
  return (
    <button
      type={type}
      className={cn(
        "inline-flex select-none items-center justify-center font-medium transition-colors duration-150 active:translate-y-px disabled:pointer-events-none disabled:opacity-45",
        BUTTON_VARIANTS[variant],
        BUTTON_SIZES[size],
        className
      )}
      {...props}
    >
      {children}
    </button>
  );
}

export function IconButton({
  label,
  children,
  className,
  ...props
}: ButtonHTMLAttributes<HTMLButtonElement> & {
  label: string;
  children: ReactNode;
}) {
  return (
    <Button
      variant="secondary"
      size="icon"
      aria-label={label}
      title={label}
      className={className}
      {...props}
    >
      {children}
    </Button>
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
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ delay, duration: 0.25, ease: "easeOut" }}
      className={className}
    >
      {children}
    </motion.div>
  );
}

/* Shared motion vocabulary. One spring for structure, one for small pops,
   so everything on the page moves with the same physical character. */
export const SPRING_SOFT = { type: "spring", stiffness: 380, damping: 34, mass: 0.8 } as const;
export const SPRING_POP = { type: "spring", stiffness: 420, damping: 22, mass: 0.7 } as const;

const staggerGroupVariants: Variants = {
  hidden: {},
  show: { transition: { staggerChildren: 0.06 } },
};

const staggerItemVariants: Variants = {
  hidden: { opacity: 0, y: 12 },
  show: { opacity: 1, y: 0, transition: SPRING_SOFT },
};

/** Wrap a tool's sections so they cascade in instead of appearing at once. */
export function StaggerGroup({
  children,
  className,
}: {
  children: ReactNode;
  className?: string;
}) {
  return (
    <motion.div
      variants={staggerGroupVariants}
      initial="hidden"
      animate="show"
      className={className}
    >
      {children}
    </motion.div>
  );
}

export function StaggerItem({
  children,
  className,
}: {
  children: ReactNode;
  className?: string;
}) {
  return (
    <motion.div variants={staggerItemVariants} className={className}>
      {children}
    </motion.div>
  );
}

/** Spring entrance for results that arrive after an action (payloads,
    signatures, verdicts). Keyed remounts replay it on each new result. */
export function PopIn({
  children,
  className,
}: {
  children: ReactNode;
  className?: string;
}) {
  return (
    <motion.div
      initial={{ opacity: 0, y: 8, scale: 0.98 }}
      animate={{ opacity: 1, y: 0, scale: 1 }}
      transition={SPRING_SOFT}
      className={className}
    >
      {children}
    </motion.div>
  );
}

/** Height-animated disclosure, used for ciphertext views and the wallet
    import form. Content unmounts when closed. */
export function Collapse({
  open,
  children,
  className,
}: {
  open: boolean;
  children: ReactNode;
  className?: string;
}) {
  return (
    <AnimatePresence initial={false}>
      {open && (
        <motion.div
          initial={{ height: 0, opacity: 0 }}
          animate={{ height: "auto", opacity: 1 }}
          exit={{ height: 0, opacity: 0 }}
          transition={{ duration: 0.22, ease: [0.16, 1, 0.3, 1] }}
          className={cn("overflow-hidden", className)}
        >
          {children}
        </motion.div>
      )}
    </AnimatePresence>
  );
}

export function SegmentedControl<T extends string | number>({
  options,
  value,
  onChange,
  label,
  className,
}: {
  options: { value: T; label: string; hint?: string }[];
  value: T;
  onChange: (value: T) => void;
  label: string;
  className?: string;
}) {
  const buttonRefs = useRef(new Map<T, HTMLButtonElement>());

  // Standard radio-group keyboard behaviour: arrows move and select, and only
  // the active option sits in the tab order.
  const handleKeyDown = (event: React.KeyboardEvent<HTMLDivElement>) => {
    const currentIndex = options.findIndex((option) => option.value === value);
    let nextIndex = -1;

    if (event.key === "ArrowRight" || event.key === "ArrowDown") {
      nextIndex = (currentIndex + 1) % options.length;
    } else if (event.key === "ArrowLeft" || event.key === "ArrowUp") {
      nextIndex = (currentIndex - 1 + options.length) % options.length;
    }

    if (nextIndex >= 0) {
      event.preventDefault();
      const nextValue = options[nextIndex].value;
      onChange(nextValue);
      buttonRefs.current.get(nextValue)?.focus();
    }
  };

  return (
    <div
      role="radiogroup"
      aria-label={label}
      onKeyDown={handleKeyDown}
      className={clsx(
        "grid gap-1 rounded-lg border border-white/10 bg-surface-inset p-1",
        className
      )}
      style={{ gridTemplateColumns: `repeat(${options.length}, minmax(0, 1fr))` }}
    >
      {options.map((option) => {
        const active = option.value === value;
        return (
          <button
            key={String(option.value)}
            ref={(node) => {
              if (node) {
                buttonRefs.current.set(option.value, node);
              } else {
                buttonRefs.current.delete(option.value);
              }
            }}
            type="button"
            role="radio"
            aria-checked={active}
            tabIndex={active ? 0 : -1}
            onClick={() => onChange(option.value)}
            className={clsx(
              "rounded-md px-2 py-2 text-center transition-colors duration-150",
              active
                ? "bg-white/[0.08] text-zinc-50"
                : "text-zinc-500 hover:bg-white/[0.04] hover:text-zinc-300"
            )}
          >
            <span className="block text-[13px] font-medium leading-4">{option.label}</span>
            {option.hint && (
              <span
                className={clsx(
                  "mt-0.5 block text-[11px] leading-4",
                  active ? "text-zinc-400" : "text-zinc-600"
                )}
              >
                {option.hint}
              </span>
            )}
          </button>
        );
      })}
    </div>
  );
}

export function EmptyState({
  icon,
  title,
  children,
  className,
}: {
  icon?: ReactNode;
  title: string;
  children?: ReactNode;
  className?: string;
}) {
  return (
    <div
      className={clsx(
        "rounded-lg border border-dashed border-white/10 bg-white/[0.02] px-5 py-8 text-center",
        className
      )}
    >
      {icon && (
        <div className="mx-auto mb-3 flex h-10 w-10 items-center justify-center rounded-lg border border-white/[0.08] bg-white/[0.04] text-zinc-500">
          {icon}
        </div>
      )}
      <p className="text-sm font-medium text-zinc-300">{title}</p>
      {children && <p className="mx-auto mt-1.5 max-w-sm text-[13px] leading-5 text-zinc-500">{children}</p>}
    </div>
  );
}

export function FileUpload({
  onFileSelect,
  accept = ".json",
  label = "Load file",
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
      <Button
        variant="secondary"
        size="sm"
        onClick={() => inputRef.current?.click()}
        className={className}
      >
        <Upload className="h-3.5 w-3.5" />
        {label}
      </Button>
    </>
  );
}
