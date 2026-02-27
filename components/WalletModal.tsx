"use client";

import { useState } from "react";
import { useWallet } from "@/components/WalletContext";
import { Lock, Unlock, Key, AlertCircle, X } from "lucide-react";
import { Card, NeonButton, FadeIn } from "@/components/ui/Motion";

export default function WalletModal({ onClose }: { onClose: () => void }) {
  const { isLocked, hasWallet, unlockWallet, createWallet, lockWallet } = useWallet();
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError("");
    setLoading(true);

    try {
      if (!hasWallet) {
        if (password.length < 6) throw new Error("Password must be at least 6 characters.");
        await createWallet(password);
      } else if (isLocked) {
        const success = await unlockWallet(password);
        if (!success) throw new Error("Incorrect password.");
      }
      onClose();
    } catch (err: any) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="fixed inset-0 z-[100] flex items-center justify-center p-4 bg-black/60 backdrop-blur-sm">
      <FadeIn className="w-full max-w-md relative">
        <button onClick={onClose} className="absolute top-4 right-4 text-slate-400 hover:text-white z-10">
          <X className="w-5 h-5" />
        </button>
        
        <Card className="border-indigo-500/30 relative overflow-hidden">
          <div className="absolute top-0 left-0 w-full h-1 bg-gradient-to-r from-indigo-500 to-violet-500" />
          
          <div className="text-center mb-6 pt-4">
            <div className="w-12 h-12 bg-indigo-500/10 rounded-full flex items-center justify-center mx-auto mb-3 border border-indigo-500/20">
              {isLocked ? <Lock className="w-6 h-6 text-indigo-400" /> : <Unlock className="w-6 h-6 text-emerald-400" />}
            </div>
            <h2 className="text-xl font-bold text-white">Browser Wallet</h2>
            <p className="text-slate-400 text-sm mt-1">
              {!hasWallet 
                ? "Create a master password to encrypt your saved keys."
                : isLocked 
                  ? "Enter your master password to unlock your keys."
                  : "Your wallet is currently unlocked."}
            </p>
          </div>

          {isLocked || !hasWallet ? (
            <form onSubmit={handleSubmit} className="space-y-4">
              <div>
                <label className="block text-sm font-medium text-slate-300 mb-1">Master Password</label>
                <div className="relative">
                  <Key className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-500" />
                  <input
                    type="password"
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    className="w-full bg-slate-900 border border-slate-700 rounded-lg py-2 pl-10 pr-4 text-white focus:ring-2 focus:ring-indigo-500 focus:outline-none transition-all"
                    placeholder="Enter password..."
                    autoFocus
                  />
                </div>
              </div>

              {error && (
                <div className="p-3 bg-red-500/10 border border-red-500/20 rounded-lg text-xs text-red-200 flex items-center gap-2">
                  <AlertCircle className="w-4 h-4" /> {error}
                </div>
              )}

              <NeonButton type="submit" disabled={loading || !password} className="w-full">
                {loading ? "Processing..." : (!hasWallet ? "Create Wallet" : "Unlock Wallet")}
              </NeonButton>
            </form>
          ) : (
            <div className="space-y-4">
              <div className="p-4 bg-emerald-500/10 border border-emerald-500/20 rounded-lg text-center">
                <p className="text-emerald-300 text-sm font-medium">Wallet is ready to use.</p>
              </div>
              <NeonButton onClick={() => { lockWallet(); onClose(); }} variant="secondary" className="w-full">
                Lock Wallet
              </NeonButton>
            </div>
          )}
        </Card>
      </FadeIn>
    </div>
  );
}