"use client";

import Image from "next/image";
import { KeyboardEvent, useEffect, useRef, useState } from "react";
import clsx from "clsx";
import { AnimatePresence, MotionConfig, motion } from "framer-motion";
import {
  Clock,
  Github,
  Home as HomeIcon,
  KeyRound,
  Lock,
  MessageSquare,
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
import { WalletProvider, useWallet } from "@/components/WalletContext";
import { NetworkProvider, useNetwork } from "@/components/NetworkContext";
import { TabId, WorkbenchProvider, useWorkbench } from "@/components/WorkbenchContext";

const TABS: ReadonlyArray<{
  id: TabId;
  label: string;
  icon: typeof HomeIcon;
  title: string;
  description: string;
}> = [
  {
    id: "home",
    label: "Home",
    icon: HomeIcon,
    title: "",
    description: "",
  },
  {
    id: "keygen",
    label: "Keys",
    icon: KeyRound,
    title: "Key generation",
    description:
      "Create an RSA key pair in your browser, then export it or save it to the wallet.",
  },
  {
    id: "encrypt",
    label: "Encrypt",
    icon: Lock,
    title: "Encrypt a message",
    description: "Encrypt text with the recipient's public key, using OAEP or textbook RSA.",
  },
  {
    id: "decrypt",
    label: "Decrypt",
    icon: Unlock,
    title: "Decrypt a payload",
    description: "Recover the plaintext from an encrypted payload with the matching private key.",
  },
  {
    id: "sign",
    label: "Sign",
    icon: PenTool,
    title: "Sign a message",
    description: "Produce an RSA-PSS signature that ties a message to your private key.",
  },
  {
    id: "verify",
    label: "Verify",
    icon: ShieldCheck,
    title: "Verify a signature",
    description:
      "Check a signature against the original message and the signer's public key.",
  },
  {
    id: "network",
    label: "Peer chat",
    icon: MessageSquare,
    title: "Peer chat",
    description: "Connect two browsers over WebRTC and exchange RSA-encrypted messages.",
  },
  {
    id: "history",
    label: "History",
    icon: Clock,
    title: "Session history",
    description: "What you've done this session. Nothing here survives a refresh.",
  },
];

function WalletButton() {
  const { hasWallet, isLocked, keys } = useWallet();
  const [showWallet, setShowWallet] = useState(false);

  const label = !hasWallet
    ? "Set up wallet"
    : isLocked
      ? "Unlock wallet"
      : `Wallet (${keys.length})`;

  return (
    <>
      <button
        type="button"
        onClick={() => setShowWallet(true)}
        className="inline-flex h-9 items-center gap-2 rounded-lg border border-white/10 bg-white/[0.04] px-3 text-[13px] font-medium text-zinc-200 transition-colors duration-150 hover:border-white/20 hover:bg-white/[0.08]"
      >
        {!hasWallet || isLocked ? (
          <Lock className="h-3.5 w-3.5 text-zinc-500" />
        ) : (
          <Vault className="h-3.5 w-3.5 text-indigo-400" />
        )}
        {label}
      </button>
      {showWallet && <WalletModal onClose={() => setShowWallet(false)} />}
    </>
  );
}

function TabBar() {
  const { activeTab, selectTab } = useWorkbench();
  const { unread } = useNetwork();
  const tabRefs = useRef(new Map<TabId, HTMLButtonElement>());

  useEffect(() => {
    tabRefs.current.get(activeTab)?.scrollIntoView({
      behavior: "smooth",
      inline: "nearest",
      block: "nearest",
    });
  }, [activeTab]);

  const handleKeyDown = (event: KeyboardEvent<HTMLDivElement>) => {
    const currentIndex = TABS.findIndex((tab) => tab.id === activeTab);
    let nextIndex = -1;

    if (event.key === "ArrowRight") {
      nextIndex = (currentIndex + 1) % TABS.length;
    } else if (event.key === "ArrowLeft") {
      nextIndex = (currentIndex - 1 + TABS.length) % TABS.length;
    } else if (event.key === "Home") {
      nextIndex = 0;
    } else if (event.key === "End") {
      nextIndex = TABS.length - 1;
    }

    if (nextIndex >= 0) {
      event.preventDefault();
      const nextId = TABS[nextIndex].id;
      selectTab(nextId);
      tabRefs.current.get(nextId)?.focus();
    }
  };

  return (
    <div className="relative">
      <div
        role="tablist"
        aria-label="CrypticComm tools"
        onKeyDown={handleKeyDown}
        className="nav-scroll mx-auto flex max-w-6xl items-stretch gap-1 overflow-x-auto px-2 sm:px-4"
      >
        {TABS.map((tab) => {
          const active = activeTab === tab.id;
          const Icon = tab.icon;
          const showUnread = tab.id === "network" && unread > 0 && !active;
          return (
            <button
              key={tab.id}
              ref={(node) => {
                if (node) {
                  tabRefs.current.set(tab.id, node);
                } else {
                  tabRefs.current.delete(tab.id);
                }
              }}
              type="button"
              role="tab"
              id={`tab-${tab.id}`}
              aria-selected={active}
              aria-controls={`panel-${tab.id}`}
              tabIndex={active ? 0 : -1}
              onClick={() => selectTab(tab.id)}
              className={clsx(
                "relative flex shrink-0 items-center gap-2 px-3 py-2.5 text-sm transition-colors duration-150",
                active ? "text-zinc-50" : "text-zinc-500 hover:text-zinc-300"
              )}
            >
              <Icon className="h-4 w-4" />
              {tab.label}
              {showUnread && (
                <span
                  aria-label={`${unread} unread message${unread === 1 ? "" : "s"}`}
                  className="ml-0.5 inline-flex h-4 min-w-4 animate-pop items-center justify-center rounded-md bg-indigo-500 px-1 font-mono text-[10px] font-semibold leading-none text-white"
                >
                  {unread > 9 ? "9+" : unread}
                </span>
              )}
              {active && (
                <motion.div
                  layoutId="tab-underline"
                  className="absolute inset-x-3 -bottom-px h-0.5 rounded-full bg-indigo-400"
                  transition={{ type: "spring", bounce: 0.2, duration: 0.45 }}
                />
              )}
            </button>
          );
        })}
      </div>
      {/* Edge fade hints that the tab row scrolls on narrow screens. */}
      <div
        aria-hidden
        className="pointer-events-none absolute inset-y-0 right-0 w-8 bg-gradient-to-l from-[#0a0a0e] to-transparent sm:hidden"
      />
    </div>
  );
}

function HomeContent() {
  const { activeTab, selectTab } = useWorkbench();
  const activeTabMeta = TABS.find((tab) => tab.id === activeTab) ?? TABS[0];

  return (
    <div className="flex min-h-dvh flex-col">
      <a
        href="#content"
        className="sr-only focus:not-sr-only focus:absolute focus:left-4 focus:top-4 focus:z-50 focus:rounded-lg focus:bg-indigo-600 focus:px-3 focus:py-2 focus:text-sm focus:text-white"
      >
        Skip to content
      </a>

      <div className="sticky top-0 z-40 border-b border-white/[0.08] bg-[#0a0a0e]/90 backdrop-blur">
        <header className="mx-auto flex h-14 max-w-6xl items-center justify-between gap-3 px-4 sm:px-6">
          <div className="flex min-w-0 items-center gap-2.5">
            <Image src={favicon} alt="" className="h-7 w-7 shrink-0 object-contain" priority />
            <span className="truncate text-[15px] font-semibold tracking-tight text-zinc-100">
              CrypticComm
            </span>
          </div>
          <div className="flex items-center gap-2">
            <WalletButton />
            <a
              href="https://github.com/rsvptr/crypticcomm/"
              target="_blank"
              rel="noreferrer"
              aria-label="View the source on GitHub"
              title="View the source on GitHub"
              className="inline-flex h-9 w-9 items-center justify-center rounded-lg border border-white/10 bg-white/[0.04] text-zinc-400 transition-colors duration-150 hover:border-white/20 hover:text-zinc-100"
            >
              <Github className="h-4 w-4" />
            </a>
          </div>
        </header>
        <TabBar />
      </div>

      <main id="content" className="mx-auto w-full max-w-6xl flex-1 px-4 py-6 sm:px-6 sm:py-8">
        {activeTab !== "home" && (
          <header className="mb-5">
            <h1 className="text-lg font-semibold tracking-tight text-zinc-100">
              {activeTabMeta.title}
            </h1>
            <p className="mt-1 max-w-2xl text-sm leading-6 text-zinc-500">
              {activeTabMeta.description}
            </p>
          </header>
        )}

        <section
          id={`panel-${activeTab}`}
          role="tabpanel"
          aria-labelledby={`tab-${activeTab}`}
        >
          <AnimatePresence mode="wait">
            <motion.div
              key={activeTab}
              initial={{ opacity: 0, y: 6 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -4 }}
              transition={{ duration: 0.16, ease: "easeOut" }}
            >
              {activeTab === "home" && <HomeTab onSelectTab={selectTab} />}
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
      </main>

      <footer className="border-t border-white/[0.06]">
        <div className="mx-auto flex max-w-6xl flex-col gap-1.5 px-4 py-5 text-[13px] leading-5 text-zinc-600 sm:flex-row sm:items-center sm:justify-between sm:px-6">
          <p>
            Cryptography runs locally in your browser. Built as a coursework project, not an
            audited product.
          </p>
          <p className="shrink-0 font-mono text-xs">
            {new Date().getFullYear()} CrypticComm, MIT license
          </p>
        </div>
      </footer>
    </div>
  );
}

export default function Home() {
  return (
    <MotionConfig reducedMotion="user">
      <WalletProvider>
        <HistoryProvider>
          <ToastProvider>
            <WorkbenchProvider>
              <NetworkProvider>
                <HomeContent />
              </NetworkProvider>
            </WorkbenchProvider>
          </ToastProvider>
        </HistoryProvider>
      </WalletProvider>
    </MotionConfig>
  );
}
