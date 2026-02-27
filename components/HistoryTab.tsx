"use client";

import { useHistory } from "@/components/HistoryContext";
import { Card, FadeIn, NeonButton } from "@/components/ui/Motion";
import { Clock, Trash2, Lock, Unlock, PenTool, ShieldCheck } from "lucide-react";

export default function HistoryTab() {
  const { history, clearHistory } = useHistory();

  const getIcon = (type: string) => {
    switch (type) {
      case "Encrypt": return <Lock className="w-4 h-4 text-emerald-400" />;
      case "Decrypt": return <Unlock className="w-4 h-4 text-indigo-400" />;
      case "Sign": return <PenTool className="w-4 h-4 text-purple-400" />;
      case "Verify": return <ShieldCheck className="w-4 h-4 text-blue-400" />;
      default: return <Clock className="w-4 h-4 text-slate-400" />;
    }
  };

  return (
    <div className="space-y-6">
      <FadeIn className="max-w-4xl mx-auto space-y-6">
        <div className="flex justify-between items-center bg-slate-900/50 p-4 rounded-xl border border-slate-800">
          <div className="flex items-center gap-2">
            <Clock className="w-5 h-5 text-indigo-400" />
            <h2 className="text-xl font-semibold text-slate-100">Session History</h2>
          </div>
          {history.length > 0 && (
            <button onClick={clearHistory} className="text-sm text-slate-400 hover:text-red-400 flex items-center gap-1 transition-colors">
              <Trash2 className="w-4 h-4" /> Clear History
            </button>
          )}
        </div>

        {history.length === 0 ? (
          <Card className="text-center py-12">
            <Clock className="w-12 h-12 text-slate-700 mx-auto mb-4 opacity-50" />
            <h3 className="text-lg font-medium text-slate-300">No History Yet</h3>
            <p className="text-slate-500 mt-2">Your encryption, decryption, and signature events for this session will appear here.</p>
          </Card>
        ) : (
          <div className="space-y-4">
            {history.map((item) => (
              <Card key={item.id} className="relative overflow-hidden group">
                <div className="flex justify-between items-start mb-2">
                  <div className="flex items-center gap-2">
                    {getIcon(item.type)}
                    <span className="font-medium text-slate-200">{item.type}</span>
                    {item.details.status && (
                      <span className={`text-xs px-2 py-0.5 rounded-full ${item.details.status === "Success" ? "bg-emerald-500/10 text-emerald-400" : "bg-red-500/10 text-red-400"}`}>
                        {item.details.status}
                      </span>
                    )}
                  </div>
                  <span className="text-xs text-slate-500">
                    {new Date(item.timestamp).toLocaleTimeString()}
                  </span>
                </div>
                
                {item.details.keyName && (
                  <div className="text-xs text-indigo-300/80 mb-2">Identity: {item.details.keyName}</div>
                )}
                
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mt-4">
                  {item.details.message && (
                    <div className="bg-slate-950/50 p-3 rounded-lg border border-slate-800/50">
                      <div className="text-xs text-slate-500 mb-1">Input / Message</div>
                      <div className="text-sm text-slate-300 font-mono truncate">{item.details.message}</div>
                    </div>
                  )}
                  {item.details.output && (
                    <div className="bg-slate-950/50 p-3 rounded-lg border border-slate-800/50">
                      <div className="text-xs text-slate-500 mb-1">Output</div>
                      <div className="text-sm text-slate-300 font-mono truncate">{item.details.output}</div>
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