"use client";

import Image from "next/image";
import { useEffect, useMemo, useState } from "react";
import clsx from "clsx";
import { AnimatePresence, motion } from "framer-motion";
import {
  CheckCircle2,
  Clock,
  Github,
  Home as HomeIcon,
  KeyRound,
  Lock,
  Network,
  PenTool,
  ShieldCheck,
  Unlock,
  Vault,
} from "lucide-react";
import favicon from "@/assets/favicon.png";
import HomeTab from "@/components/HomeTab";
import KeyGen from "@/components/KeyGen";
import Encrypt from "@/components/Encrypt";
import Decrypt from "@/components/Decrypt";
import Sign from "@/components/Sign";
import Verify from "@/components/Verify";
import NetworkTab from "@/components/Network";
import HistoryTab from "@/components/HistoryTab";
import WalletModal from "@/components/WalletModal";
import { HistoryProvider } from "@/components/HistoryContext";
import { ToastProvider } from "@/components/ToastContext";
import { Card, NeonButton } from "@/components/ui/Motion";
import { WalletProvider, useWallet } from "@/components/WalletContext";

const TABS = [
  {
    id: "home",
    label: "Home",
    icon: HomeIcon,
    eyebrow: "Start",
    description: "Get the lay of the land, then jump into a focused cryptography workflow.",
  },
  {
    id: "keygen",
    label: "KeyGen",
    icon: KeyRound,
    eyebrow: "Create",
    description: "Generate browser-only RSA identities with export-ready PEM and JSON output.",
  },
  {
    id: "encrypt",
    label: "Encrypt",
    icon: Lock,
    eyebrow: "Protect",
    description: "Encrypt plain text with OAEP or textbook RSA and export the segmented payload.",
  },
  {
    id: "decrypt",
    label: "Decrypt",
    icon: Unlock,
    eyebrow: "Recover",
    description: "Decrypt payloads, inspect segment health, and copy the recovered plaintext.",
  },
  {
    id: "sign",
    label: "Sign",
    icon: PenTool,
    eyebrow: "Prove",
    description: "Create RSA-PSS signatures to prove authorship without exposing your private key.",
  },
  {
    id: "verify",
    label: "Verify",
    icon: ShieldCheck,
    eyebrow: "Validate",
    description: "Confirm message integrity with public-key verification and instant status feedback.",
  },
  {
    id: "network",
    label: "Network",
    icon: Network,
    eyebrow: "Connect",
    description: "Exchange public keys automatically and send encrypted messages over WebRTC.",
  },
  {
    id: "history",
    label: "History",
    icon: Clock,
    eyebrow: "Review",
    description: "Track this session's cryptographic actions without persisting sensitive activity.",
  },
] as const;

function Header() {
  const { hasWallet, isLocked, keys } = useWallet();
  const [showWallet, setShowWallet] = useState(false);

  return (
    <>
      <header className="sticky top-0 z-50 border-b border-white/10 bg-[rgba(5,8,20,0.76)] backdrop-blur-2xl">
        <div className="mx-auto flex max-w-7xl items-center justify-between gap-4 px-4 py-4 sm:px-6">
          <div className="flex min-w-0 items-center gap-3">
            <div className="relative flex h-12 w-12 shrink-0 items-center justify-center rounded-2xl border border-cyan-400/20 bg-white/10 shadow-[0_18px_40px_rgba(67,97,238,0.24)]">
              <Image
                src={favicon}
                alt="CrypticComm icon"
                className="h-8 w-8 object-contain"
                priority
              />
            </div>
            <div className="min-w-0">
              <p className="text-[11px] font-semibold uppercase tracking-[0.28em] text-cyan-200/70">
                Privacy-first RSA Lab
              </p>
              <h1 className="truncate text-lg font-semibold tracking-tight text-white sm:text-xl">
                CrypticComm
              </h1>
            </div>
          </div>

          <div className="flex items-center gap-2 sm:gap-3">
            <div className="hidden h-12 items-center gap-2 rounded-2xl border border-white/10 bg-white/5 px-4 text-sm font-medium text-slate-200 sm:inline-flex">
              <CheckCircle2
                className={`h-4 w-4 ${isLocked ? "text-amber-300" : "text-emerald-400"}`}
              />
              {hasWallet
                ? isLocked
                  ? "Wallet locked"
                  : `${keys.length} saved identit${keys.length === 1 ? "y" : "ies"}`
                : "No wallet yet"}
            </div>

            <NeonButton
              variant="secondary"
              size="md"
              onClick={() => setShowWallet(true)}
              className="min-w-[168px] px-4"
            >
              {isLocked ? (
                <Lock className="h-4 w-4 text-rose-300" />
              ) : (
                <Vault className="h-4 w-4 text-emerald-300" />
              )}
              <span>{isLocked ? "Open Wallet" : "Wallet Ready"}</span>
            </NeonButton>

            <a
              href="https://github.com/rsvptr/crypticcomm/"
              target="_blank"
              rel="noreferrer"
              aria-label="Open CrypticComm repository on GitHub"
              className="icon-btn shrink-0"
            >
              <Github className="h-4 w-4" />
            </a>
          </div>
        </div>
      </header>
      {showWallet && <WalletModal onClose={() => setShowWallet(false)} />}
    </>
  );
}

function ToolButton({
  active,
  mobile = false,
  icon: Icon,
  label,
  eyebrow,
  id,
  controls,
  onClick,
}: {
  active: boolean;
  mobile?: boolean;
  icon: (typeof TABS)[number]["icon"];
  label: string;
  eyebrow: string;
  id: string;
  controls: string;
  onClick: () => void;
}) {
  return (
    <button
      type="button"
      role="tab"
      aria-selected={active}
      aria-controls={controls}
      id={id}
      onClick={onClick}
      className={clsx(
        "relative overflow-hidden border text-left transition duration-200",
        mobile
          ? "min-w-[152px] rounded-[22px] px-4 py-3"
          : "flex w-full items-center gap-3 rounded-[22px] px-4 py-4",
        active
          ? "border-cyan-400/30 bg-cyan-400/10 text-white shadow-[0_18px_45px_rgba(34,211,238,0.12)]"
          : "border-white/10 bg-white/5 text-slate-300 hover:border-white/20 hover:bg-white/10"
      )}
    >
      {active && (
        <motion.div
          layoutId={mobile ? "mobile-tab-highlight" : "desktop-tab-highlight"}
          className="absolute inset-0 bg-[linear-gradient(135deg,rgba(34,211,238,0.08),rgba(67,97,238,0.14),transparent)]"
          transition={{ type: "spring", bounce: 0.18, duration: 0.5 }}
        />
      )}

      <div
        className={clsx(
          "relative z-10 flex items-center gap-3",
          mobile ? "flex-col items-start gap-4" : "w-full"
        )}
      >
        <div
          className={clsx(
            "flex h-11 w-11 shrink-0 items-center justify-center rounded-2xl border",
            active
              ? "border-cyan-300/30 bg-white/10 text-cyan-100"
              : "border-white/10 bg-white/5 text-slate-300"
          )}
        >
          <Icon className="h-4 w-4" />
        </div>
        <div className="min-w-0">
          <p className="text-[11px] font-semibold uppercase tracking-[0.24em] text-slate-500">
            {eyebrow}
          </p>
          <p className="mt-1 text-base font-semibold tracking-tight">{label}</p>
        </div>
      </div>
    </button>
  );
}

function HomeContent() {
  const [activeTab, setActiveTab] = useState<(typeof TABS)[number]["id"]>("home");

  useEffect(() => {
    const savedTab = window.localStorage.getItem("crypticcomm-active-tab");
    if (savedTab && TABS.some((tab) => tab.id === savedTab)) {
      setActiveTab(savedTab as (typeof TABS)[number]["id"]);
    }
  }, []);

  useEffect(() => {
    window.localStorage.setItem("crypticcomm-active-tab", activeTab);
  }, [activeTab]);

  const activeTabMeta = useMemo(
    () => TABS.find((tab) => tab.id === activeTab) ?? TABS[0],
    [activeTab]
  );
  const ActiveTabIcon = activeTabMeta.icon;

  return (
    <main className="relative min-h-screen overflow-x-hidden">
      <Header />

      <div className="lg:hidden sticky top-[81px] z-40 border-b border-white/10 bg-[rgba(5,8,20,0.84)] px-4 py-3 backdrop-blur-2xl sm:px-6">
        <div
          role="tablist"
          aria-label="CrypticComm tools"
          className="nav-scroll flex gap-3 overflow-x-auto pb-1"
        >
          {TABS.map((tab) => (
            <ToolButton
              key={tab.id}
              active={activeTab === tab.id}
              mobile
              icon={tab.icon}
              label={tab.label}
              eyebrow={tab.eyebrow}
              id={`mobile-tab-${tab.id}`}
              controls={`panel-${tab.id}`}
              onClick={() => setActiveTab(tab.id)}
            />
          ))}
        </div>
      </div>

      <div className="relative z-10 mx-auto max-w-7xl px-4 py-6 sm:px-6 lg:py-8">
        <div className="grid gap-6 lg:grid-cols-[280px_minmax(0,1fr)] lg:items-start">
          <aside className="hidden lg:block">
            <div className="sticky top-[98px] space-y-4">
              <Card className="p-3">
                <div className="px-3 pb-3 pt-2">
                  <p className="text-[11px] font-semibold uppercase tracking-[0.28em] text-cyan-200/70">
                    Workspace
                  </p>
                  <h2 className="mt-2 text-xl font-semibold tracking-tight text-white">
                    Jump between tools
                  </h2>
                  <p className="mt-2 text-sm leading-6 text-slate-400">
                    Navigation stays pinned while you work, and Home gives you a clean starting
                    point instead of dropping straight into a tool.
                  </p>
                </div>

                <div role="tablist" aria-label="CrypticComm tools" className="space-y-2">
                  {TABS.map((tab) => (
                    <ToolButton
                      key={tab.id}
                      active={activeTab === tab.id}
                      icon={tab.icon}
                      label={tab.label}
                      eyebrow={tab.eyebrow}
                      id={`desktop-tab-${tab.id}`}
                      controls={`panel-${tab.id}`}
                      onClick={() => setActiveTab(tab.id)}
                    />
                  ))}
                </div>
              </Card>
            </div>
          </aside>

          <div className="space-y-5">
            <Card className="px-5 py-5 sm:px-6">
              <div className="flex flex-col gap-5 xl:flex-row xl:items-center xl:justify-between">
                <div className="flex items-start gap-4">
                  <div className="flex h-14 w-14 shrink-0 items-center justify-center rounded-[20px] border border-cyan-400/20 bg-cyan-400/10 text-cyan-100">
                    <ActiveTabIcon className="h-6 w-6" />
                  </div>
                  <div>
                    <p className="text-[11px] font-semibold uppercase tracking-[0.28em] text-cyan-200/70">
                      Current tool
                    </p>
                    <h2 className="mt-2 text-3xl font-semibold tracking-tight text-white">
                      {activeTabMeta.label}
                    </h2>
                    <p className="mt-3 max-w-2xl text-sm leading-7 text-slate-300 sm:text-base">
                      {activeTabMeta.description}
                    </p>
                  </div>
                </div>

                <div className="grid gap-3 sm:grid-cols-2 xl:w-[360px]">
                  <div className="rounded-2xl border border-white/10 bg-white/5 px-4 py-4">
                    <p className="text-[11px] uppercase tracking-[0.24em] text-slate-500">
                      Navigation
                    </p>
                    <p className="mt-2 text-sm font-medium leading-6 text-slate-100">
                      Tabs stay visible while you work.
                    </p>
                  </div>
                  <div className="rounded-2xl border border-white/10 bg-white/5 px-4 py-4">
                    <p className="text-[11px] uppercase tracking-[0.24em] text-slate-500">
                      Focus
                    </p>
                    <p className="mt-2 text-sm font-medium leading-6 text-slate-100">
                      Home for orientation, then one focused tool per view.
                    </p>
                  </div>
                </div>
              </div>
            </Card>

            <section
              id={`panel-${activeTab}`}
              role="tabpanel"
              aria-label={`${activeTabMeta.label} panel`}
              className="min-h-[420px]"
            >
              <AnimatePresence mode="wait">
                <motion.div
                  key={activeTab}
                  initial={{ opacity: 0, y: 12, scale: 0.99 }}
                  animate={{ opacity: 1, y: 0, scale: 1 }}
                  exit={{ opacity: 0, y: -10, scale: 0.99 }}
                  transition={{ duration: 0.24, ease: "easeOut" }}
                >
                  {activeTab === "home" && <HomeTab onSelectTab={setActiveTab} />}
                  {activeTab === "keygen" && <KeyGen />}
                  {activeTab === "encrypt" && <Encrypt />}
                  {activeTab === "decrypt" && <Decrypt />}
                  {activeTab === "sign" && <Sign />}
                  {activeTab === "verify" && <Verify />}
                  {activeTab === "network" && <NetworkTab />}
                  {activeTab === "history" && <HistoryTab />}
                </motion.div>
              </AnimatePresence>
            </section>
          </div>
        </div>

        <footer className="mt-8 flex flex-col gap-3 border-t border-white/10 px-1 pt-6 text-sm text-slate-500 sm:flex-row sm:items-center sm:justify-between">
          <p>All cryptographic operations run locally in your browser unless you explicitly share data.</p>
          <p className="font-mono text-xs tracking-[0.24em] text-slate-600">
            Copyright {new Date().getFullYear()} CRYPTICCOMM
          </p>
        </footer>
      </div>
    </main>
  );
}

export default function Home() {
  return (
    <WalletProvider>
      <HistoryProvider>
        <ToastProvider>
          <HomeContent />
        </ToastProvider>
      </HistoryProvider>
    </WalletProvider>
  );
}
