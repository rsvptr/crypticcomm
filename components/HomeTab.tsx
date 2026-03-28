"use client";

import { Home, Lock, Network, PenTool, ShieldCheck, Sparkles } from "lucide-react";
import { Card, FadeIn, NeonButton } from "@/components/ui/Motion";

type HomeQuickTab = "keygen" | "network";

export default function HomeTab({ onSelectTab }: { onSelectTab: (tabId: HomeQuickTab) => void }) {
  return (
    <div className="space-y-6">
      <FadeIn>
        <Card className="overflow-hidden px-6 py-7 sm:px-8">
          <div className="grid gap-6 xl:grid-cols-[1.15fr_0.85fr] xl:items-center">
            <div>
              <div className="glass-pill text-cyan-100">
                <Sparkles className="h-3.5 w-3.5" />
                Browser-native cryptography workspace
              </div>
              <h2 className="mt-5 text-4xl font-semibold tracking-tight text-white sm:text-5xl">
                Learn RSA, signatures, and encrypted peer messaging in one place.
              </h2>
              <p className="mt-4 max-w-2xl text-base leading-7 text-slate-300 sm:text-lg">
                Start with key generation, then move through encryption, signatures, and the
                WebRTC chat flow without leaving the browser or sending your private keys anywhere.
              </p>

              <div className="mt-7 flex flex-wrap gap-3">
                <NeonButton onClick={() => onSelectTab("keygen")}>
                  <Lock className="h-4 w-4" />
                  Generate keys
                </NeonButton>
                <NeonButton
                  variant="secondary"
                  onClick={() => onSelectTab("network")}
                >
                  <Network className="h-4 w-4" />
                  Open network lab
                </NeonButton>
              </div>
            </div>

            <div className="grid gap-3 sm:grid-cols-3 xl:grid-cols-1">
              <div className="metric-tile">
                <p className="text-[11px] uppercase tracking-[0.24em] text-slate-500">
                  Privacy
                </p>
                <p className="mt-2 text-lg font-semibold text-white">Client-side only</p>
                <p className="mt-2 text-sm leading-6 text-slate-400">
                  Keys stay in your browser unless you export them yourself.
                </p>
              </div>
              <div className="metric-tile">
                <p className="text-[11px] uppercase tracking-[0.24em] text-slate-500">
                  Interop
                </p>
                <p className="mt-2 text-lg font-semibold text-white">PEM + JSON</p>
                <p className="mt-2 text-sm leading-6 text-slate-400">
                  Use the app for demos, then move the same identities into other tools.
                </p>
              </div>
              <div className="metric-tile">
                <p className="text-[11px] uppercase tracking-[0.24em] text-slate-500">
                  Workflow
                </p>
                <p className="mt-2 text-lg font-semibold text-white">One tab per task</p>
                <p className="mt-2 text-sm leading-6 text-slate-400">
                  Jump between focused tools without losing your place in the workspace.
                </p>
              </div>
            </div>
          </div>
        </Card>
      </FadeIn>

      <FadeIn delay={0.08} className="grid gap-4 lg:grid-cols-3">
        <Card className="px-5 py-5">
          <div className="flex items-center gap-3">
            <div className="flex h-11 w-11 items-center justify-center rounded-2xl border border-cyan-400/20 bg-cyan-400/10 text-cyan-100">
              <Home className="h-5 w-5" />
            </div>
            <div>
              <p className="text-[11px] uppercase tracking-[0.24em] text-slate-500">Step 1</p>
              <h3 className="mt-1 text-xl font-semibold text-white">Generate or import keys</h3>
            </div>
          </div>
          <p className="mt-4 text-sm leading-7 text-slate-400">
            Start in KeyGen to create an identity, then save it to the wallet for quick access
            across the rest of the app.
          </p>
        </Card>

        <Card className="px-5 py-5">
          <div className="flex items-center gap-3">
            <div className="flex h-11 w-11 items-center justify-center rounded-2xl border border-indigo-400/20 bg-indigo-400/10 text-indigo-100">
              <PenTool className="h-5 w-5" />
            </div>
            <div>
              <p className="text-[11px] uppercase tracking-[0.24em] text-slate-500">Step 2</p>
              <h3 className="mt-1 text-xl font-semibold text-white">Encrypt or sign</h3>
            </div>
          </div>
          <p className="mt-4 text-sm leading-7 text-slate-400">
            Use focused tabs for encryption, decryption, signatures, and verification instead of
            crowding all workflows into a single long page.
          </p>
        </Card>

        <Card className="px-5 py-5">
          <div className="flex items-center gap-3">
            <div className="flex h-11 w-11 items-center justify-center rounded-2xl border border-emerald-400/20 bg-emerald-400/10 text-emerald-100">
              <ShieldCheck className="h-5 w-5" />
            </div>
            <div>
              <p className="text-[11px] uppercase tracking-[0.24em] text-slate-500">Step 3</p>
              <h3 className="mt-1 text-xl font-semibold text-white">Test the full flow</h3>
            </div>
          </div>
          <p className="mt-4 text-sm leading-7 text-slate-400">
            Move into the Network tab to exchange peer IDs and test end-to-end encrypted chat with
            identities from the wallet.
          </p>
        </Card>
      </FadeIn>
    </div>
  );
}
