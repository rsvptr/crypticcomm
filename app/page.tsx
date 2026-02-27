"use client";

import { useState } from "react";
import KeyGen from "@/components/KeyGen";
import Encrypt from "@/components/Encrypt";
import Decrypt from "@/components/Decrypt";
import Sign from "@/components/Sign";
import Verify from "@/components/Verify";
import NetworkTab from "@/components/Network";
import HistoryTab from "@/components/HistoryTab";
import { WalletProvider, useWallet } from "@/components/WalletContext";
import { HistoryProvider } from "@/components/HistoryContext";
import WalletModal from "@/components/WalletModal";
import { KeyRound, Lock, Unlock, PenTool, ShieldCheck, Github, Network, Clock } from "lucide-react";
import clsx from "clsx";
import { motion, AnimatePresence } from "framer-motion";

const TABS = [
  { id: "keygen", label: "KeyGen", icon: KeyRound },
  { id: "encrypt", label: "Encrypt", icon: Lock },
  { id: "decrypt", label: "Decrypt", icon: Unlock },
  { id: "sign", label: "Sign", icon: PenTool },
  { id: "verify", label: "Verify", icon: ShieldCheck },
  { id: "network", label: "Network", icon: Network },
  { id: "history", label: "History", icon: Clock },
];

function Header() {
  const { isLocked } = useWallet();
  const [showModal, setShowModal] = useState(false);

  return (
    <>
      <header className="border-b border-white/5 bg-slate-900/40 backdrop-blur-xl sticky top-0 z-50">
        <div className="max-w-7xl mx-auto px-4 h-16 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="w-9 h-9 bg-gradient-to-tr from-indigo-600 to-violet-600 rounded-xl flex items-center justify-center shadow-lg shadow-indigo-500/20 ring-1 ring-white/10">
              <ShieldCheck className="w-5 h-5 text-white" />
            </div>
            <h1 className="text-xl font-bold bg-clip-text text-transparent bg-gradient-to-r from-indigo-200 to-white tracking-tight">
              CrypticComm
            </h1>
          </div>
          <div className="flex items-center gap-4">
            <button 
              onClick={() => setShowModal(true)}
              className="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 border border-slate-700 text-sm font-medium transition-colors text-slate-300"
            >
              {isLocked ? <Lock className="w-4 h-4 text-red-400" /> : <Unlock className="w-4 h-4 text-emerald-400" />}
              Wallet
            </button>
            <a 
              href="https://github.com" 
              target="_blank" 
              className="p-2 hover:bg-white/5 rounded-full transition-colors text-slate-400 hover:text-white"
            >
              <Github className="w-5 h-5" />
            </a>
          </div>
        </div>
      </header>
      {showModal && <WalletModal onClose={() => setShowModal(false)} />}
    </>
  );
}

export default function Home() {
  const [activeTab, setActiveTab] = useState("keygen");

  return (
    <WalletProvider>
      <HistoryProvider>
        <main className="min-h-screen bg-[#0a0f1e] text-slate-200 font-sans selection:bg-indigo-500/30 overflow-x-hidden relative">
          
          {/* Animated Background Mesh */}
          <div className="fixed inset-0 z-0 pointer-events-none opacity-20">
              <div className="absolute inset-0 bg-[radial-gradient(circle_at_50%_50%,rgba(76,29,149,0.2),transparent_70%)]"></div>
              <div className="absolute top-0 left-0 w-full h-full bg-[url('https://grainy-gradients.vercel.app/noise.svg')] opacity-20"></div>
          </div>

          <Header />

          <div className="max-w-6xl mx-auto px-4 py-12 relative z-10">
            
            {/* Hero Text */}
            <div className="text-center mb-12">
              <h2 className="text-3xl sm:text-4xl font-bold text-white mb-4 tracking-tight">
                Secure Communication, <span className="text-indigo-400">Democratized.</span>
              </h2>
              <p className="text-slate-400 max-w-2xl mx-auto text-lg">
                Client-side RSA encryption, decryption, and digital signatures. <br className="hidden sm:block"/> 
                Your keys never leave your device.
              </p>
            </div>

            {/* Navigation Tabs */}
            <div className="flex flex-wrap justify-center gap-2 mb-12 bg-slate-900/60 p-2 rounded-2xl border border-white/5 backdrop-blur-md w-fit mx-auto shadow-2xl shadow-black/50">
              {TABS.map((tab) => {
                const Icon = tab.icon;
                const isActive = activeTab === tab.id;
                return (
                  <button
                    key={tab.id}
                    onClick={() => setActiveTab(tab.id)}
                    className={clsx(
                      "relative flex items-center gap-2 px-5 py-2.5 rounded-xl text-sm font-medium transition-all duration-300",
                      isActive ? "text-white" : "text-slate-400 hover:text-slate-200 hover:bg-white/5"
                    )}
                  >
                    {isActive && (
                      <motion.div
                        layoutId="activeTab"
                        className="absolute inset-0 bg-indigo-600 rounded-xl shadow-lg shadow-indigo-500/25"
                        transition={{ type: "spring", bounce: 0.2, duration: 0.6 }}
                      />
                    )}
                    <span className="relative z-10 flex items-center gap-2">
                      <Icon className="w-4 h-4" /> {tab.label}
                    </span>
                  </button>
                );
              })}
            </div>

            {/* Content Area */}
            <div className="min-h-[400px]">
              <AnimatePresence mode="wait">
                <motion.div
                  key={activeTab}
                  initial={{ opacity: 0, y: 10, scale: 0.98 }}
                  animate={{ opacity: 1, y: 0, scale: 1 }}
                  exit={{ opacity: 0, y: -10, scale: 0.98 }}
                  transition={{ duration: 0.3 }}
                >
                  {activeTab === "keygen" && <KeyGen />}
                  {activeTab === "encrypt" && <Encrypt />}
                  {activeTab === "decrypt" && <Decrypt />}
                  {activeTab === "sign" && <Sign />}
                  {activeTab === "verify" && <Verify />}
                  {activeTab === "network" && <NetworkTab />}
                  {activeTab === "history" && <HistoryTab />}
                </motion.div>
              </AnimatePresence>
            </div>
            
            {/* Footer */}
            <footer className="mt-20 text-center text-slate-600 text-sm border-t border-white/5 pt-8">
              <p>© {new Date().getFullYear()} CrypticComm. Open Source & Privacy First.</p>
            </footer>
          </div>
        </main>
      </HistoryProvider>
    </WalletProvider>
  );
}
