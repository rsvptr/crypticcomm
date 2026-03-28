"use client";

import { useEffect, useMemo, useState } from "react";
import {
  AlertCircle,
  Copy,
  Download,
  Key,
  Lock,
  Trash2,
  Unlock,
  Vault,
  X,
} from "lucide-react";
import { useWallet } from "@/components/WalletContext";
import { useToast } from "@/components/ToastContext";
import { Card, NeonButton, FadeIn } from "@/components/ui/Motion";

function downloadTextFile(filename: string, content: string, type = "application/json") {
  const blob = new Blob([content], { type });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = filename;
  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);
  URL.revokeObjectURL(url);
}

export default function WalletModal({ onClose }: { onClose: () => void }) {
  const { keys, isLocked, hasWallet, unlockWallet, createWallet, lockWallet, deleteKey } =
    useWallet();
  const toast = useToast();
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);
  const [pendingDeleteId, setPendingDeleteId] = useState<string | null>(null);
  const newestKey = useMemo(() => keys[0], [keys]);

  useEffect(() => {
    const previousOverflow = document.body.style.overflow;
    const previousActiveElement = document.activeElement instanceof HTMLElement
      ? document.activeElement
      : null;

    document.body.style.overflow = "hidden";

    return () => {
      document.body.style.overflow = previousOverflow;
      previousActiveElement?.focus();
    };
  }, []);

  useEffect(() => {
    const handleKeyDown = (event: KeyboardEvent) => {
      if (event.key === "Escape") {
        onClose();
      }
    };

    window.addEventListener("keydown", handleKeyDown);
    return () => window.removeEventListener("keydown", handleKeyDown);
  }, [onClose]);

  useEffect(() => {
    if (!pendingDeleteId) {
      return;
    }

    const timer = window.setTimeout(() => setPendingDeleteId(null), 4000);
    return () => window.clearTimeout(timer);
  }, [pendingDeleteId]);

  const handleSubmit = async (event: React.FormEvent) => {
    event.preventDefault();
    setError("");
    setLoading(true);

    try {
      if (!hasWallet) {
        if (password.length < 8) {
          throw new Error("Use at least 8 characters for the master password.");
        }
        await createWallet(password);
        toast.success({
          title: "Wallet created",
          description: "Your browser vault is ready to store RSA identities securely.",
        });
      } else if (isLocked) {
        const unlockedCount = await unlockWallet(password);
        toast.success({
          title: "Wallet unlocked",
          description: `Loaded ${unlockedCount} saved identit${unlockedCount === 1 ? "y" : "ies"}.`,
        });
      }

      onClose();
    } catch (err) {
      const message = err instanceof Error ? err.message : "Unable to access the wallet.";
      setError(message);
    } finally {
      setLoading(false);
    }
  };

  const handleDeleteKey = async (id: string, name: string) => {
    if (pendingDeleteId !== id) {
      setPendingDeleteId(id);
      return;
    }

    setPendingDeleteId(null);

    try {
      await deleteKey(id);
      toast.success({
        title: "Identity removed",
        description: `${name} was deleted from the encrypted wallet.`,
      });
    } catch (err) {
      toast.error({
        title: "Delete failed",
        description: err instanceof Error ? err.message : "The key could not be removed.",
      });
    }
  };

  const handleCancelDelete = (id: string) => {
    if (pendingDeleteId !== id) {
      return;
    }

    setPendingDeleteId(null);
  };

  const handleCopyPublicKey = async (content: string) => {
    try {
      await navigator.clipboard.writeText(content);
      toast.success({
        title: "Public key copied",
        description: "The JSON public key is now on your clipboard.",
      });
    } catch {
      toast.error({
        title: "Copy failed",
        description: "Clipboard access was denied by the browser.",
      });
    }
  };

  return (
    <div
      className="fixed inset-0 z-[100] flex items-center justify-center bg-black/70 p-4 backdrop-blur-md"
      onClick={(event) => {
        if (event.target === event.currentTarget) {
          onClose();
        }
      }}
    >
      <FadeIn className="w-full max-w-3xl">
        <Card
          className="max-h-[92vh] overflow-hidden border-cyan-400/20 p-0"
          role="dialog"
          aria-modal="true"
          aria-labelledby="wallet-modal-title"
        >
          <div className="flex items-start justify-between gap-4 border-b border-white/10 px-6 py-5">
            <div>
              <p className="text-[11px] font-semibold uppercase tracking-[0.28em] text-cyan-200/70">
                Encrypted wallet
              </p>
              <h2
                id="wallet-modal-title"
                className="mt-1 text-2xl font-semibold tracking-tight text-white"
              >
                Browser vault
              </h2>
              <p className="mt-2 max-w-xl text-sm leading-6 text-slate-400">
                Save identities locally with AES-GCM encryption so you can move through the app
                without pasting keys between tools.
              </p>
            </div>
            <button
              type="button"
              onClick={onClose}
              className="icon-btn mt-1"
              aria-label="Close wallet modal"
            >
              <X className="h-4 w-4" />
            </button>
          </div>

          <div className="max-h-[calc(92vh-92px)] overflow-y-auto px-6 py-6">
            {isLocked || !hasWallet ? (
              <form onSubmit={handleSubmit} className="grid gap-6 lg:grid-cols-[1fr_0.9fr]">
                <div className="space-y-4">
                  <div className="rounded-[26px] border border-white/10 bg-white/5 p-5">
                    <div className="flex items-center gap-3">
                      <div className="rounded-2xl border border-cyan-400/20 bg-cyan-400/10 p-3 text-cyan-100">
                        {isLocked ? <Lock className="h-5 w-5" /> : <Vault className="h-5 w-5" />}
                      </div>
                      <div>
                        <h3 className="text-lg font-semibold text-white">
                          {!hasWallet ? "Create your vault" : "Unlock your vault"}
                        </h3>
                        <p className="text-sm text-slate-400">
                          {!hasWallet
                            ? "Set a master password to encrypt wallet contents in localStorage."
                            : "Enter your master password to restore encrypted identities into memory."}
                        </p>
                      </div>
                    </div>
                  </div>

                  <div>
                    <label className="mb-2 block text-sm font-medium text-slate-300">
                      Master password
                    </label>
                    <div className="relative">
                      <Key className="pointer-events-none absolute left-4 top-1/2 h-4 w-4 -translate-y-1/2 text-slate-500" />
                      <input
                        type="password"
                        value={password}
                        onChange={(event) => setPassword(event.target.value)}
                        className="field-input pl-11"
                        placeholder={!hasWallet ? "Create a strong password" : "Enter password"}
                        autoFocus
                      />
                    </div>
                  </div>

                  {error && (
                    <div className="rounded-2xl border border-rose-500/20 bg-rose-500/10 p-3 text-sm text-rose-100">
                      <div className="flex items-start gap-2">
                        <AlertCircle className="mt-0.5 h-4 w-4 shrink-0" />
                        <span>{error}</span>
                      </div>
                    </div>
                  )}

                  <NeonButton type="submit" disabled={loading || !password} className="w-full">
                    {loading
                      ? "Processing..."
                      : !hasWallet
                        ? "Create encrypted wallet"
                        : "Unlock wallet"}
                  </NeonButton>
                </div>

                <div className="rounded-[28px] border border-white/10 bg-white/5 p-5">
                  <p className="text-[11px] font-semibold uppercase tracking-[0.28em] text-slate-500">
                    Wallet benefits
                  </p>
                  <div className="mt-4 space-y-3 text-sm leading-6 text-slate-300">
                    <div className="rounded-2xl border border-white/10 bg-[#060916] px-4 py-3">
                      Identities become selectable in Encrypt, Decrypt, Sign, Verify, and Network.
                    </div>
                    <div className="rounded-2xl border border-white/10 bg-[#060916] px-4 py-3">
                      The encrypted vault persists across refreshes, while unlocked keys remain only
                      in current memory.
                    </div>
                    <div className="rounded-2xl border border-white/10 bg-[#060916] px-4 py-3">
                      A longer password directly improves resistance against local brute-force
                      attempts.
                    </div>
                  </div>
                </div>
              </form>
            ) : (
              <div className="space-y-6">
                <div className="grid gap-4 md:grid-cols-3">
                  <div className="metric-tile">
                    <p className="text-[11px] uppercase tracking-[0.26em] text-slate-500">
                      Saved identities
                    </p>
                    <p className="mt-3 text-3xl font-semibold tracking-tight text-white">
                      {keys.length}
                    </p>
                  </div>
                  <div className="metric-tile">
                    <p className="text-[11px] uppercase tracking-[0.26em] text-slate-500">
                      Latest identity
                    </p>
                    <p className="mt-3 text-lg font-semibold tracking-tight text-white">
                      {newestKey?.name ?? "No keys yet"}
                    </p>
                  </div>
                  <div className="metric-tile">
                    <p className="text-[11px] uppercase tracking-[0.26em] text-slate-500">
                      Wallet status
                    </p>
                    <div className="mt-3 inline-flex items-center gap-2 rounded-full border border-emerald-500/20 bg-emerald-500/10 px-3 py-1.5 text-sm text-emerald-200">
                      <Unlock className="h-4 w-4" />
                      Unlocked
                    </div>
                  </div>
                </div>

                {keys.length === 0 ? (
                  <div className="rounded-[28px] border border-white/10 bg-white/5 px-6 py-10 text-center">
                    <Vault className="mx-auto h-10 w-10 text-slate-600" />
                    <h3 className="mt-4 text-lg font-semibold text-white">No saved identities yet</h3>
                    <p className="mt-2 text-sm text-slate-400">
                      Generate a key pair in the KeyGen tab, then save it here for one-click reuse
                      throughout the app.
                    </p>
                  </div>
                ) : (
                  <div className="space-y-3">
                    {keys.map((key) => (
                      <div
                        key={key.id}
                        className="rounded-[26px] border border-white/10 bg-white/5 p-4"
                      >
                        <div className="flex flex-col gap-4 md:flex-row md:items-center md:justify-between">
                          <div>
                            <p className="text-lg font-semibold tracking-tight text-white">
                              {key.name}
                            </p>
                            <p className="mt-1 text-sm text-slate-400">
                              Added {new Date(key.createdAt).toLocaleString()}
                            </p>
                          </div>
                          <div className="flex flex-wrap gap-2">
                            <NeonButton
                              variant="secondary"
                              onClick={() =>
                                handleCopyPublicKey(JSON.stringify(key.keys.public, null, 2))
                              }
                            >
                              <Copy className="h-4 w-4" />
                              Copy public key
                            </NeonButton>
                            <NeonButton
                              variant="secondary"
                              onClick={() =>
                                downloadTextFile(
                                  `${key.name.replace(/[^a-zA-Z0-9]+/g, "_")}_bundle.json`,
                                  JSON.stringify(key.keys, null, 2)
                                )
                              }
                            >
                              <Download className="h-4 w-4" />
                              Export bundle
                            </NeonButton>
                            <NeonButton
                              variant="danger"
                              onClick={() => handleDeleteKey(key.id, key.name)}
                            >
                              <Trash2 className="h-4 w-4" />
                              {pendingDeleteId === key.id ? "Confirm delete" : "Delete"}
                            </NeonButton>
                            {pendingDeleteId === key.id && (
                              <NeonButton
                                variant="ghost"
                                onClick={() => handleCancelDelete(key.id)}
                              >
                                Cancel
                              </NeonButton>
                            )}
                          </div>
                        </div>
                        {pendingDeleteId === key.id && (
                          <div className="mt-3 rounded-2xl border border-rose-500/20 bg-rose-500/10 px-4 py-3 text-sm text-rose-100">
                            Click delete again to permanently remove this identity from the local
                            encrypted wallet.
                          </div>
                        )}
                      </div>
                    ))}
                  </div>
                )}

                <div className="flex flex-col gap-3 border-t border-white/10 pt-2 sm:flex-row sm:justify-end">
                  <NeonButton
                    variant="secondary"
                    onClick={() => {
                      lockWallet();
                      toast.info({
                        title: "Wallet locked",
                        description: "Saved identities remain encrypted in localStorage.",
                      });
                      onClose();
                    }}
                  >
                    Lock wallet
                  </NeonButton>
                  <NeonButton onClick={onClose}>Done</NeonButton>
                </div>
              </div>
            )}
          </div>
        </Card>
      </FadeIn>
    </div>
  );
}
