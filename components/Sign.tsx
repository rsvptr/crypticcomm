"use client";

import { useMemo, useState } from "react";
import {
  Check,
  Copy,
  Download,
  FileSignature,
  PenTool,
  RefreshCcw,
} from "lucide-react";
import { dictToPrivJwk, pemToRSAKeyDict, signMessage } from "@/lib/rsa";
import { useHistory } from "@/components/HistoryContext";
import { useToast } from "@/components/ToastContext";
import { useWallet } from "@/components/WalletContext";
import { Card, FadeIn, FileUpload, NeonButton } from "@/components/ui/Motion";

interface ParsedPrivateKey {
  n: string;
  e: string;
  d: string;
  p?: string;
  q?: string;
}

function downloadTextFile(filename: string, content: string, type: string) {
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

export default function Sign() {
  const { keys } = useWallet();
  const { addHistory } = useHistory();
  const toast = useToast();

  const [privKeyInput, setPrivKeyInput] = useState("");
  const [message, setMessage] = useState("");
  const [signature, setSignature] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);
  const [selectedWalletKeyId, setSelectedWalletKeyId] = useState("");

  const selectedWalletKey = useMemo(
    () => keys.find((key) => key.id === selectedWalletKeyId),
    [keys, selectedWalletKeyId]
  );

  const parsePrivateKey = async (rawInput: string): Promise<ParsedPrivateKey> => {
    const trimmedInput = rawInput.trim();

    if (trimmedInput.startsWith("-----BEGIN PRIVATE KEY-----")) {
      return pemToRSAKeyDict(trimmedInput, "private");
    }

    let parsed: unknown;
    try {
      parsed = JSON.parse(trimmedInput);
    } catch {
      throw new Error("Private key must be valid JSON or a PEM block.");
    }

    if (
      !parsed ||
      typeof parsed !== "object" ||
      typeof (parsed as ParsedPrivateKey).d !== "string"
    ) {
      throw new Error("Private key JSON must include the RSA private values.");
    }

    return parsed as ParsedPrivateKey;
  };

  const handleSign = async () => {
    setError(null);
    setLoading(true);
    setSignature("");
    setCopied(false);

    try {
      if (!privKeyInput.trim() || !message.trim()) {
        throw new Error("Private key and message are required.");
      }

      const privKeyData = await parsePrivateKey(privKeyInput);
      const privJwk = dictToPrivJwk(privKeyData);
      const nextSignature = await signMessage(message, privJwk);

      setSignature(nextSignature);
      addHistory({
        type: "Sign",
        details: {
          message,
          output: nextSignature,
          keyName: selectedWalletKey?.name,
          status: "Success",
        },
      });
      toast.success({
        title: "Signature created",
        description: "The RSA-PSS signature is ready to copy or verify.",
      });
    } catch (error) {
      const messageText =
        error instanceof Error ? error.message : "The message could not be signed.";
      setError(messageText);
      addHistory({
        type: "Sign",
        details: { status: "Error", message: messageText },
      });
    } finally {
      setLoading(false);
    }
  };

  const handleCopy = async () => {
    if (!signature) {
      return;
    }

    try {
      await navigator.clipboard.writeText(signature);
      setCopied(true);
      window.setTimeout(() => setCopied(false), 2000);
      toast.success({
        title: "Signature copied",
        description: "The hex signature is now on your clipboard.",
      });
    } catch {
      toast.error({
        title: "Copy failed",
        description: "Clipboard access was blocked by the browser.",
      });
    }
  };

  const clearAll = () => {
    setSelectedWalletKeyId("");
    setPrivKeyInput("");
    setMessage("");
    setSignature("");
    setError(null);
    setCopied(false);
  };

  return (
    <div className="space-y-6">
      <FadeIn className="grid gap-6 xl:grid-cols-[minmax(0,1fr)_380px]">
        <div className="space-y-6">
          <Card className="px-5 py-6">
            <div className="flex flex-col gap-4 border-b border-white/10 pb-4 sm:flex-row sm:items-start sm:justify-between">
              <div>
                <p className="text-[11px] font-semibold uppercase tracking-[0.28em] text-cyan-200/70">
                  Signer identity
                </p>
                <h2 className="mt-2 flex items-center gap-2 text-2xl font-semibold tracking-tight text-white">
                  <PenTool className="h-5 w-5 text-cyan-300" />
                  Private key
                </h2>
                <p className="mt-2 text-sm leading-7 text-slate-400">
                  Load the signing key that will generate the RSA-PSS proof of authorship.
                </p>
              </div>
              <FileUpload
                onFileSelect={(data) => {
                  setPrivKeyInput(data);
                  setSelectedWalletKeyId("");
                }}
                label="Load key"
                accept=".json,.pem,.txt"
              />
            </div>

            {keys.length > 0 && (
              <div className="mt-5">
                <label className="mb-2 block text-sm font-medium text-slate-300">
                  Saved identities
                </label>
                <select
                  onChange={(event) => {
                    const key = keys.find((entry) => entry.id === event.target.value);
                    if (key) {
                      setSelectedWalletKeyId(key.id);
                      setPrivKeyInput(JSON.stringify(key.keys.private, null, 2));
                    } else {
                      setSelectedWalletKeyId("");
                      setPrivKeyInput("");
                    }
                  }}
                  value={selectedWalletKeyId}
                  className="field-input"
                >
                  <option value="">Choose a wallet identity</option>
                  {keys.map((key) => (
                    <option key={key.id} value={key.id}>
                      {key.name}
                    </option>
                  ))}
                </select>
              </div>
            )}

            <div className="mt-5">
              {selectedWalletKey ? (
                <div className="rounded-[26px] border border-rose-500/20 bg-rose-500/10 px-5 py-5">
                  <p className="text-[11px] font-semibold uppercase tracking-[0.26em] text-rose-200/80">
                    Using wallet identity
                  </p>
                  <h3 className="mt-2 text-xl font-semibold tracking-tight text-white">
                    {selectedWalletKey.name}
                  </h3>
                  <p className="mt-2 text-sm leading-6 text-rose-100/80">
                    The signing key is loaded in memory and ready to create a new signature.
                  </p>
                  <button
                    type="button"
                    onClick={() => setSelectedWalletKeyId("")}
                    className="mt-4 text-sm font-medium text-cyan-200 transition hover:text-white"
                  >
                    Edit raw key
                  </button>
                </div>
              ) : (
                <textarea
                  value={privKeyInput}
                  onChange={(event) => {
                    setPrivKeyInput(event.target.value);
                    setSelectedWalletKeyId("");
                  }}
                  placeholder="Paste private key JSON or PEM..."
                  className="field-area min-h-[220px] text-rose-50/80"
                />
              )}
            </div>
          </Card>

          <Card className="px-5 py-6">
            <div className="flex flex-col gap-4 border-b border-white/10 pb-4 sm:flex-row sm:items-start sm:justify-between">
              <div>
                <p className="text-[11px] font-semibold uppercase tracking-[0.28em] text-cyan-200/70">
                  Message
                </p>
                <h2 className="mt-2 flex items-center gap-2 text-2xl font-semibold tracking-tight text-white">
                  <FileSignature className="h-5 w-5 text-cyan-300" />
                  Content to sign
                </h2>
                <p className="mt-2 text-sm leading-7 text-slate-400">
                  The exact text here is what the verifier will later check against the signature.
                </p>
              </div>
              <FileUpload onFileSelect={setMessage} label="Load text" accept=".txt,.md" />
            </div>

            <textarea
              value={message}
              onChange={(event) => setMessage(event.target.value)}
              placeholder="Type the message you want to sign..."
              className="field-area mt-5 min-h-[220px] text-sm"
            />
          </Card>
        </div>

        <div className="space-y-6">
          <Card className="px-5 py-6">
            <div className="flex items-start justify-between gap-4">
              <div>
                <p className="text-[11px] font-semibold uppercase tracking-[0.28em] text-cyan-200/70">
                  Action
                </p>
                <h2 className="mt-2 text-2xl font-semibold tracking-tight text-white">
                  Generate signature
                </h2>
              </div>
              <button
                type="button"
                onClick={clearAll}
                className="inline-flex items-center gap-2 rounded-full border border-white/10 bg-white/5 px-3 py-2 text-xs font-medium text-slate-400 transition hover:border-white/20 hover:text-white"
              >
                <RefreshCcw className="h-3.5 w-3.5" />
                Clear all
              </button>
            </div>

            <p className="mt-4 text-sm leading-7 text-slate-400">
              Signatures are produced with RSA-PSS and SHA-256 using the private key above.
            </p>

            {error && (
              <div className="mt-4 rounded-[22px] border border-rose-500/20 bg-rose-500/10 px-4 py-4 text-sm text-rose-100">
                {error}
              </div>
            )}

            <NeonButton
              onClick={handleSign}
              disabled={loading || !privKeyInput.trim() || !message.trim()}
              className="mt-6 w-full"
              size="lg"
            >
              {loading ? "Signing..." : "Generate signature"}
            </NeonButton>
          </Card>

          <Card className="px-5 py-6">
            <div className="flex items-start justify-between gap-3">
              <div>
                <p className="text-[11px] font-semibold uppercase tracking-[0.28em] text-cyan-200/70">
                  Output
                </p>
                <h2 className="mt-2 text-2xl font-semibold tracking-tight text-white">
                  Digital signature
                </h2>
              </div>
              {signature && (
                <button
                  type="button"
                  onClick={handleCopy}
                  className="icon-btn"
                  aria-label="Copy digital signature"
                >
                  {copied ? (
                    <Check className="h-4 w-4 text-emerald-300" />
                  ) : (
                    <Copy className="h-4 w-4" />
                  )}
                </button>
              )}
            </div>

            {signature ? (
              <>
                <div className="mt-5 grid gap-3 sm:grid-cols-3">
                  <div className="metric-tile">
                    <p className="text-[11px] uppercase tracking-[0.24em] text-slate-500">
                      Format
                    </p>
                    <p className="mt-2 text-xl font-semibold text-white">Hex</p>
                  </div>
                  <div className="metric-tile">
                    <p className="text-[11px] uppercase tracking-[0.24em] text-slate-500">
                      Length
                    </p>
                    <p className="mt-2 text-xl font-semibold text-white">{signature.length}</p>
                  </div>
                  <div className="metric-tile">
                    <p className="text-[11px] uppercase tracking-[0.24em] text-slate-500">
                      Bytes
                    </p>
                    <p className="mt-2 text-xl font-semibold text-white">
                      {signature.length / 2}
                    </p>
                  </div>
                </div>

                <pre className="code-block mt-5 max-h-[320px] break-all text-emerald-50/80">
                  {signature}
                </pre>

                <NeonButton
                  variant="secondary"
                  onClick={() =>
                    downloadTextFile(
                      `signature-${new Date().toISOString().replace(/[:.]/g, "-")}.txt`,
                      signature,
                      "text/plain"
                    )
                  }
                  className="mt-4 w-full"
                >
                  <Download className="h-4 w-4" />
                  Download signature
                </NeonButton>
              </>
            ) : (
              <div className="mt-5 rounded-[26px] border border-dashed border-white/10 bg-white/5 px-5 py-10 text-center">
                <p className="text-lg font-semibold text-white">No signature yet</p>
                <p className="mt-2 text-sm leading-6 text-slate-400">
                  Generate a signature to produce a portable hex proof that can be checked in the
                  Verify tab.
                </p>
              </div>
            )}
          </Card>
        </div>
      </FadeIn>
    </div>
  );
}
