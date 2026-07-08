"use client";

import { useEffect, useId, useState } from "react";
import { createPortal } from "react-dom";
import { motion } from "framer-motion";
import { Copy, Download, FilePlus2, Lock, Trash2, Unlock, Vault, X } from "lucide-react";
import { useWallet } from "@/components/WalletContext";
import { useToast } from "@/components/ToastContext";
import { keyFingerprint, pemToRSAKeyDict, RSAKeyDict } from "@/lib/rsa";
import { downloadTextFile, safeFileBaseName } from "@/lib/download";
import { Button, Collapse, EmptyState, FileUpload, IconButton } from "@/components/ui/Motion";

function validatePrivateNumbers(priv: { n: string; e: string; d: string; p?: string; q?: string }) {
  let n: bigint;
  let e: bigint;
  let d: bigint;
  try {
    n = BigInt(priv.n);
    e = BigInt(priv.e);
    d = BigInt(priv.d);
  } catch {
    throw new Error("Key values have to be integer strings.");
  }

  if (n <= 0n || e < 3n || d <= 0n) {
    throw new Error("Key values are out of range for an RSA key.");
  }

  if (priv.p && priv.q) {
    try {
      if (BigInt(priv.p) * BigInt(priv.q) !== n) {
        throw new Error("mismatch");
      }
    } catch {
      throw new Error(
        "The prime factors don't multiply to the modulus, so this key is inconsistent."
      );
    }
  }
}

/**
 * Accepts what the app itself exports: a full key bundle, a bare private key
 * JSON, or a PKCS#8 private key PEM. Everything else is rejected with a
 * specific reason.
 */
async function parseImportedKey(raw: string): Promise<RSAKeyDict> {
  const trimmed = raw.trim();
  if (!trimmed) {
    throw new Error("Paste or load a key first.");
  }

  let parsed: unknown = null;
  try {
    parsed = JSON.parse(trimmed);
  } catch {
    // Not JSON; try PEM below.
  }

  if (parsed && typeof parsed === "object") {
    const obj = parsed as Record<string, unknown>;
    const candidate =
      obj.private && typeof obj.private === "object"
        ? (obj.private as Record<string, unknown>)
        : typeof obj.d === "string"
          ? obj
          : null;

    if (
      !candidate ||
      typeof candidate.n !== "string" ||
      typeof candidate.e !== "string" ||
      typeof candidate.d !== "string"
    ) {
      throw new Error(
        'JSON must be an exported key bundle or a private key with "n", "e", and "d".'
      );
    }

    const priv = {
      n: candidate.n,
      e: candidate.e,
      d: candidate.d,
      p: typeof candidate.p === "string" ? candidate.p : undefined,
      q: typeof candidate.q === "string" ? candidate.q : undefined,
      pem: typeof candidate.pem === "string" ? candidate.pem : undefined,
    };
    validatePrivateNumbers(priv);

    const pub =
      obj.public && typeof obj.public === "object" ? (obj.public as Record<string, unknown>) : null;
    if (pub && typeof pub.n === "string" && pub.n !== priv.n) {
      throw new Error("The bundle's public and private keys don't belong together.");
    }

    return {
      public: {
        n: priv.n,
        e: priv.e,
        pem: pub && typeof pub.pem === "string" ? pub.pem : undefined,
      },
      private: priv,
      jwk: obj.jwk && typeof obj.jwk === "object" ? (obj.jwk as JsonWebKey) : undefined,
    };
  }

  if (trimmed.includes("-----BEGIN PRIVATE KEY-----")) {
    const record = await pemToRSAKeyDict(trimmed, "private");
    return {
      public: { n: record.n, e: record.e },
      private: {
        n: record.n,
        e: record.e,
        d: record.d,
        p: record.p,
        q: record.q,
        pem: record.pem,
      },
      jwk: record.jwk,
    };
  }

  throw new Error("Paste an exported JSON bundle, a private key JSON, or a private key PEM.");
}

function KeyFingerprintLabel({ modulus }: { modulus: string }) {
  const [fingerprint, setFingerprint] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    keyFingerprint(modulus).then((fp) => {
      if (!cancelled) setFingerprint(fp);
    });
    return () => {
      cancelled = true;
    };
  }, [modulus]);

  if (!fingerprint) {
    return null;
  }

  return <span className="font-mono">{fingerprint}</span>;
}

export default function WalletModal({ onClose }: { onClose: () => void }) {
  const { keys, isLocked, hasWallet, unlockWallet, createWallet, lockWallet, saveKey, deleteKey } =
    useWallet();
  const toast = useToast();
  const passwordId = useId();
  const importAreaId = useId();
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);
  const [pendingDeleteId, setPendingDeleteId] = useState<string | null>(null);
  const [showImport, setShowImport] = useState(false);
  const [importText, setImportText] = useState("");
  const [importError, setImportError] = useState("");
  const [importing, setImporting] = useState(false);

  useEffect(() => {
    const previousOverflow = document.body.style.overflow;
    const previousActiveElement =
      document.activeElement instanceof HTMLElement ? document.activeElement : null;

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
          description: "Identities you save are now encrypted in this browser.",
        });
      } else if (isLocked) {
        const unlockedCount = await unlockWallet(password);
        toast.success({
          title: "Wallet unlocked",
          description: `Loaded ${unlockedCount} identit${unlockedCount === 1 ? "y" : "ies"}.`,
        });
      }

      onClose();
    } catch (err) {
      const message = err instanceof Error ? err.message : "Could not open the wallet.";
      setError(message);
    } finally {
      setLoading(false);
    }
  };

  const handleImport = async () => {
    setImportError("");
    setImporting(true);

    try {
      const imported = await parseImportedKey(importText);
      const saved = await saveKey(imported);
      toast.success({
        title: "Identity imported",
        description: `${saved.name} is ready to use across the app.`,
      });
      if (!imported.private.p || !imported.private.q) {
        toast.info({
          title: "Imported without prime factors",
          description:
            "OAEP decryption and signing need p and q, so this key only works in textbook mode.",
        });
      }
      setImportText("");
      setShowImport(false);
    } catch (err) {
      setImportError(err instanceof Error ? err.message : "The key could not be imported.");
    } finally {
      setImporting(false);
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
        title: "Identity deleted",
        description: `${name} was removed from the wallet.`,
      });
    } catch (err) {
      toast.error({
        title: "Delete failed",
        description: err instanceof Error ? err.message : "The key could not be removed.",
      });
    }
  };

  const handleCopyPublicKey = async (content: string) => {
    try {
      await navigator.clipboard.writeText(content);
      toast.success({ title: "Public key copied" });
    } catch {
      toast.error({
        title: "Copy failed",
        description: "The browser blocked clipboard access.",
      });
    }
  };

  // Rendered through a portal: the sticky header uses backdrop-filter, which
  // would otherwise become the containing block for this fixed overlay.
  return createPortal(
    <div
      className="fixed inset-0 z-[100] flex items-center justify-center bg-black/60 p-4 backdrop-blur-sm"
      onClick={(event) => {
        if (event.target === event.currentTarget) {
          onClose();
        }
      }}
    >
      <motion.div
        initial={{ opacity: 0, scale: 0.97, y: 8 }}
        animate={{ opacity: 1, scale: 1, y: 0 }}
        transition={{ type: "spring", stiffness: 380, damping: 32 }}
        role="dialog"
        aria-modal="true"
        aria-labelledby="wallet-modal-title"
        className="flex max-h-[90dvh] w-full max-w-xl flex-col overflow-hidden rounded-xl border border-white/10 bg-surface shadow-2xl shadow-black/50"
      >
        <div className="flex items-start justify-between gap-4 border-b border-white/[0.06] px-5 py-4">
          <div>
            <h2
              id="wallet-modal-title"
              className="text-base font-semibold tracking-tight text-zinc-100"
            >
              Wallet
            </h2>
            <p className="mt-0.5 text-[13px] leading-5 text-zinc-500">
              Saved identities, encrypted at rest in this browser.
            </p>
          </div>
          <IconButton label="Close" onClick={onClose}>
            <X className="h-4 w-4" />
          </IconButton>
        </div>

        <div className="overflow-y-auto px-5 py-5">
          {isLocked || !hasWallet ? (
            <form onSubmit={handleSubmit} className="space-y-4">
              <p className="text-[13px] leading-6 text-zinc-400">
                {!hasWallet
                  ? "Set a master password to create the wallet. Identities are encrypted with AES-GCM before they reach localStorage, using a key derived from this password. There is no reset if you forget it."
                  : "Enter the master password to load your saved identities into memory. They stay decrypted only until you lock the wallet or close the page."}
              </p>

              <div>
                <label className="field-label" htmlFor={passwordId}>
                  Master password
                </label>
                <input
                  id={passwordId}
                  type="password"
                  value={password}
                  onChange={(event) => setPassword(event.target.value)}
                  className="field-input"
                  placeholder={!hasWallet ? "At least 8 characters" : "Enter password"}
                  autoFocus
                />
              </div>

              {error && (
                <div role="alert" className="notice-danger">
                  {error}
                </div>
              )}

              <Button type="submit" disabled={loading || !password} className="w-full">
                {loading ? "Working" : !hasWallet ? "Create wallet" : "Unlock wallet"}
              </Button>
            </form>
          ) : (
            <div className="space-y-4">
              <div className="flex items-center justify-between gap-3">
                <p className="text-[13px] text-zinc-500">
                  {keys.length === 0
                    ? "No identities saved yet."
                    : `${keys.length} identit${keys.length === 1 ? "y" : "ies"} saved.`}
                </p>
                <div className="flex items-center gap-2">
                  <Button
                    variant="secondary"
                    size="sm"
                    onClick={() => {
                      setImportError("");
                      setShowImport((current) => !current);
                    }}
                    aria-expanded={showImport}
                  >
                    <FilePlus2 className="h-3.5 w-3.5" />
                    Import
                  </Button>
                  <span className="chip-success">
                    <Unlock className="h-3 w-3" />
                    Unlocked
                  </span>
                </div>
              </div>

              <Collapse open={showImport}>
                <div className="rounded-lg border border-white/[0.06] bg-surface-inset p-3.5">
                  <label className="field-label" htmlFor={importAreaId}>
                    Import an identity
                  </label>
                  <textarea
                    id={importAreaId}
                    value={importText}
                    onChange={(event) => setImportText(event.target.value)}
                    placeholder="Paste an exported bundle, a private key JSON, or a private key PEM"
                    className="field-area min-h-[7rem] bg-surface"
                  />
                  {importError && (
                    <div role="alert" className="notice-danger mt-2.5">
                      {importError}
                    </div>
                  )}
                  <div className="mt-2.5 flex items-center justify-between gap-2">
                    <FileUpload
                      onFileSelect={setImportText}
                      label="Load file"
                      accept=".json,.pem,.txt"
                    />
                    <Button
                      size="sm"
                      onClick={handleImport}
                      disabled={importing || !importText.trim()}
                    >
                      {importing ? "Checking" : "Import key"}
                    </Button>
                  </div>
                </div>
              </Collapse>

              {keys.length === 0 ? (
                <EmptyState icon={<Vault className="h-4 w-4" />} title="The wallet is empty">
                  Generate a key pair in the Keys tab, then save it here to reuse it across the
                  app without pasting.
                </EmptyState>
              ) : (
                <ul className="divide-y divide-white/[0.05] rounded-lg border border-white/[0.06]">
                  {keys.map((key) => (
                    <li key={key.id} className="px-3.5 py-3">
                      <div className="flex flex-wrap items-center justify-between gap-x-4 gap-y-2">
                        <div className="min-w-0">
                          <p className="truncate font-mono text-[13px] font-medium text-zinc-200">
                            {key.name}
                          </p>
                          <p className="mt-0.5 truncate text-xs text-zinc-600">
                            <KeyFingerprintLabel modulus={key.keys.public.n} /> · Added{" "}
                            {new Date(key.createdAt).toLocaleDateString()}
                          </p>
                        </div>
                        <div className="flex shrink-0 items-center gap-1.5">
                          <IconButton
                            label="Copy public key"
                            onClick={() =>
                              handleCopyPublicKey(JSON.stringify(key.keys.public, null, 2))
                            }
                          >
                            <Copy className="h-3.5 w-3.5" />
                          </IconButton>
                          <IconButton
                            label="Download key bundle"
                            onClick={() =>
                              downloadTextFile(
                                `${safeFileBaseName(key.name)}_bundle.json`,
                                JSON.stringify(key.keys, null, 2),
                                "application/json"
                              )
                            }
                          >
                            <Download className="h-3.5 w-3.5" />
                          </IconButton>
                          <Button
                            variant="danger"
                            size="sm"
                            onClick={() => handleDeleteKey(key.id, key.name)}
                          >
                            <Trash2 className="h-3.5 w-3.5" />
                            {pendingDeleteId === key.id ? "Confirm" : "Delete"}
                          </Button>
                        </div>
                      </div>
                      {pendingDeleteId === key.id && (
                        <p className="mt-2 text-xs leading-4 text-rose-300">
                          Click again to delete permanently. The exported bundle is the only
                          backup.
                        </p>
                      )}
                    </li>
                  ))}
                </ul>
              )}

              <div className="flex justify-end gap-2 border-t border-white/[0.06] pt-4">
                <Button
                  variant="secondary"
                  onClick={() => {
                    lockWallet();
                    toast.info({
                      title: "Wallet locked",
                      description: "Identities stay encrypted in localStorage.",
                    });
                    onClose();
                  }}
                >
                  <Lock className="h-4 w-4" />
                  Lock wallet
                </Button>
                <Button onClick={onClose}>Done</Button>
              </div>
            </div>
          )}
        </div>
      </motion.div>
    </div>,
    document.body
  );
}
