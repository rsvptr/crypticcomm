"use client";

import { Clock, Lock, PenTool, ShieldCheck, Trash2, Unlock } from "lucide-react";
import { useHistory } from "@/components/HistoryContext";
import { Button, Card, EmptyState, FadeIn } from "@/components/ui/Motion";

function statusChipClass(status?: string) {
  switch (status) {
    case "Success":
      return "chip-success";
    case "Partial Failure":
      return "chip-warning";
    case "Invalid":
    case "Failed":
    case "Error":
    case "Hash mismatch":
      return "chip-danger";
    default:
      return "chip-neutral";
  }
}

function typeIcon(type: string) {
  switch (type) {
    case "Encrypt":
      return <Lock className="h-3.5 w-3.5" />;
    case "Decrypt":
      return <Unlock className="h-3.5 w-3.5" />;
    case "Sign":
      return <PenTool className="h-3.5 w-3.5" />;
    case "Verify":
      return <ShieldCheck className="h-3.5 w-3.5" />;
    default:
      return <Clock className="h-3.5 w-3.5" />;
  }
}

export default function HistoryTab() {
  const { history, clearHistory } = useHistory();

  if (history.length === 0) {
    return (
      <FadeIn>
        <Card className="px-5 py-10">
          <EmptyState
            icon={<Clock className="h-4 w-4" />}
            title="Nothing here yet"
            className="border-none bg-transparent"
          >
            Encrypt, decrypt, sign, or verify something and it will show up here. The list
            lives in memory only and resets when you close or refresh the page.
          </EmptyState>
        </Card>
      </FadeIn>
    );
  }

  return (
    <FadeIn className="space-y-4">
      <div className="flex items-center justify-between gap-3">
        <p className="text-[13px] text-zinc-500">
          {history.length} entr{history.length === 1 ? "y" : "ies"} this session, newest first.
        </p>
        <Button variant="secondary" size="sm" onClick={clearHistory}>
          <Trash2 className="h-3.5 w-3.5" />
          Clear history
        </Button>
      </div>

      <Card className="divide-y divide-white/[0.05]">
        {history.map((item) => (
          <article key={item.id} className="px-4 py-4 sm:px-5">
            <div className="flex flex-wrap items-center gap-2">
              <span className="flex h-7 w-7 items-center justify-center rounded-md border border-white/[0.08] bg-white/[0.04] text-zinc-400">
                {typeIcon(item.type)}
              </span>
              <span className="text-sm font-medium text-zinc-200">{item.type}</span>
              {item.details.status && (
                <span className={statusChipClass(item.details.status)}>
                  {item.details.status}
                </span>
              )}
              {item.details.keyName && (
                <span className="hidden font-mono text-xs text-zinc-500 sm:inline">
                  {item.details.keyName}
                </span>
              )}
              <span className="ml-auto font-mono text-xs text-zinc-600">
                {new Date(item.timestamp).toLocaleTimeString([], {
                  hour: "2-digit",
                  minute: "2-digit",
                  second: "2-digit",
                })}
              </span>
            </div>

            {(item.details.message || item.details.output) && (
              <div className="mt-3 grid gap-2 lg:grid-cols-2">
                {item.details.message && (
                  <div className="min-w-0 rounded-lg border border-white/[0.05] bg-surface-inset px-3 py-2.5">
                    <p className="text-[11px] font-medium text-zinc-600">Input</p>
                    <p className="mt-1 break-words font-mono text-xs leading-5 text-zinc-400">
                      {item.details.message}
                    </p>
                  </div>
                )}
                {item.details.output && (
                  <div className="min-w-0 rounded-lg border border-white/[0.05] bg-surface-inset px-3 py-2.5">
                    <p className="text-[11px] font-medium text-zinc-600">Output</p>
                    <p className="mt-1 break-words font-mono text-xs leading-5 text-zinc-400">
                      {item.details.output}
                    </p>
                  </div>
                )}
              </div>
            )}
          </article>
        ))}
      </Card>
    </FadeIn>
  );
}
