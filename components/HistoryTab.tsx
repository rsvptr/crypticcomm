"use client";

import { useHistory } from "@/components/HistoryContext";
import { Card, FadeIn, NeonButton } from "@/components/ui/Motion";
import {
  Clock,
  Lock,
  PenTool,
  ShieldCheck,
  Trash2,
  Unlock,
} from "lucide-react";

export default function HistoryTab() {
  const { history, clearHistory } = useHistory();

  const getStatusTone = (status?: string) => {
    switch (status) {
      case "Success":
        return "border-emerald-500/20 bg-emerald-500/10 text-emerald-200";
      case "Partial Failure":
        return "border-amber-500/20 bg-amber-500/10 text-amber-200";
      case "Invalid":
      case "Failed":
      case "Error":
        return "border-rose-500/20 bg-rose-500/10 text-rose-200";
      default:
        return "border-white/10 bg-white/5 text-slate-300";
    }
  };

  const getIcon = (type: string) => {
    switch (type) {
      case "Encrypt":
        return <Lock className="h-4 w-4 text-emerald-400" />;
      case "Decrypt":
        return <Unlock className="h-4 w-4 text-indigo-400" />;
      case "Sign":
        return <PenTool className="h-4 w-4 text-purple-400" />;
      case "Verify":
        return <ShieldCheck className="h-4 w-4 text-blue-400" />;
      default:
        return <Clock className="h-4 w-4 text-slate-400" />;
    }
  };

  return (
    <div className="space-y-6">
      <FadeIn className="space-y-6">
        <Card className="px-5 py-5 sm:px-6">
          <div className="flex flex-col gap-4 lg:flex-row lg:items-center lg:justify-between">
            <div className="flex items-start gap-3">
              <div className="rounded-2xl border border-indigo-400/20 bg-indigo-400/10 p-3 text-indigo-200">
                <Clock className="h-5 w-5" />
              </div>
              <div>
                <p className="text-[11px] font-semibold uppercase tracking-[0.28em] text-slate-500">
                  Session activity
                </p>
                <h2 className="mt-2 text-2xl font-semibold tracking-tight text-white">
                  Session History
                </h2>
                <p className="mt-2 max-w-2xl text-sm leading-6 text-slate-400">
                  A rolling view of your encryption, decryption, signing, and verification actions
                  for this session only.
                </p>
              </div>
            </div>

            <div className="flex flex-col gap-3 sm:flex-row sm:items-center">
              <div className="rounded-full border border-white/10 bg-white/5 px-4 py-2 text-sm text-slate-300">
                {history.length} entr{history.length === 1 ? "y" : "ies"} this session
              </div>
              {history.length > 0 && (
                <NeonButton variant="secondary" onClick={clearHistory}>
                  <Trash2 className="h-4 w-4" />
                  Clear history
                </NeonButton>
              )}
            </div>
          </div>
        </Card>

        {history.length === 0 ? (
          <Card className="flex min-h-[320px] items-center justify-center px-6 py-10 text-center">
            <div className="max-w-xl">
              <div className="mx-auto flex h-20 w-20 items-center justify-center rounded-full border border-white/10 bg-white/5">
                <Clock className="h-10 w-10 text-slate-600" />
              </div>
              <h3 className="mt-6 text-3xl font-semibold tracking-tight text-white">
                No history yet
              </h3>
              <p className="mt-4 text-base leading-7 text-slate-400">
                Once you run encryption, decryption, signing, or verification actions, they will
                appear here so you can quickly review your recent flow.
              </p>
              <p className="mt-3 text-sm text-slate-500">
                This panel resets with the session, so sensitive activity is not kept long-term.
              </p>
            </div>
          </Card>
        ) : (
          <div className="space-y-4">
            {history.map((item) => (
              <Card key={item.id} className="relative overflow-hidden">
                <div className="flex flex-col gap-4 lg:flex-row lg:items-start lg:justify-between">
                  <div>
                    <div className="flex flex-wrap items-center gap-2">
                      <div className="rounded-xl border border-white/10 bg-white/5 p-2">
                        {getIcon(item.type)}
                      </div>
                      <span className="text-lg font-semibold tracking-tight text-slate-100">
                        {item.type}
                      </span>
                      {item.details.status && (
                        <span className={`status-badge ${getStatusTone(item.details.status)}`}>
                          {item.details.status}
                        </span>
                      )}
                    </div>

                    {item.details.keyName && (
                      <p className="mt-3 text-sm text-cyan-200/70">
                        Identity: {item.details.keyName}
                      </p>
                    )}
                  </div>

                  <div className="rounded-full border border-white/10 bg-white/5 px-3 py-1.5 text-xs text-slate-400">
                    {new Date(item.timestamp).toLocaleTimeString()}
                  </div>
                </div>

                <div className="mt-5 grid gap-4 lg:grid-cols-2">
                  {item.details.message && (
                    <div className="rounded-2xl border border-white/10 bg-[#060916] p-4">
                      <p className="text-[11px] uppercase tracking-[0.24em] text-slate-500">
                        Input / Message
                      </p>
                      <p className="mt-3 break-words font-mono text-sm leading-6 text-slate-300">
                        {item.details.message}
                      </p>
                    </div>
                  )}
                  {item.details.output && (
                    <div className="rounded-2xl border border-white/10 bg-[#060916] p-4">
                      <p className="text-[11px] uppercase tracking-[0.24em] text-slate-500">
                        Output
                      </p>
                      <p className="mt-3 break-words font-mono text-sm leading-6 text-slate-300">
                        {item.details.output}
                      </p>
                    </div>
                  )}
                </div>
              </Card>
            ))}
          </div>
        )}
      </FadeIn>
    </div>
  );
}
