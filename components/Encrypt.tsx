"use client";

import { useMemo, useState } from "react";
import {
  AlertTriangle,
  Check,
  Copy,
  Download,
  FileJson,
  Lock,
  RefreshCcw,
} from "lucide-react";
import {
  dictToPubJwk,
  encryptSegmentOAEP,
  encryptSegmentTextbook,
  pemToRSAKeyDict,
  segmentMessage,
  sha256,
} from "@/lib/rsa";
import { useHistory } from "@/components/HistoryContext";
import { useToast } from "@/components/ToastContext";
import { useWallet } from "@/components/WalletContext";
import { Card, FadeIn, FileUpload, NeonButton } from "@/components/ui/Motion";

interface EncryptedPayload {
  segments: string[];
  oaep: boolean;
  num_segments: number;
  key_bits: number;
  message_sha256: string;
  timestamp: string;
}

interface ParsedPublicKey {
  n: string;
  e: string;
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

export default function Encrypt() {
  const { keys } = useWallet();
  const { addHistory } = useHistory();
  const toast = useToast();

  const [pubKeyInput, setPubKeyInput] = useState("");
  const [message, setMessage] = useState("");
  const [useOAEP, setUseOAEP] = useState(true);
  const [loading, setLoading] = useState(false);
  const [output, setOutput] = useState<EncryptedPayload | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);
  const [selectedWalletKeyId, setSelectedWalletKeyId] = useState("");

  const selectedWalletKey = useMemo(
    () => keys.find((key) => key.id === selectedWalletKeyId),
    [keys, selectedWalletKeyId]
  );

  const outputJson = output ? JSON.stringify(output, null, 2) : "";

  const parsePublicKey = async (rawInput: string): Promise<ParsedPublicKey> => {
    const trimmedInput = rawInput.trim();

    if (trimmedInput.startsWith("-----BEGIN PUBLIC KEY-----")) {
      return pemToRSAKeyDict(trimmedInput, "public");
    }

    let parsed: unknown;
    try {
      parsed = JSON.parse(trimmedInput);
    } catch {
      throw new Error("Public key must be valid JSON or a PEM block.");
    }

    if (
      !parsed ||
      typeof parsed !== "object" ||
      typeof (parsed as ParsedPublicKey).n !== "string" ||
      typeof (parsed as ParsedPublicKey).e !== "string"
    ) {
      throw new Error("Public key JSON must include string values for n and e.");
    }

    return parsed as ParsedPublicKey;
  };

  const handleEncrypt = async () => {
    setError(null);
    setLoading(true);
    setOutput(null);
    setCopied(false);

    try {
      if (!pubKeyInput.trim() || !message.trim()) {
        throw new Error("Public key and message are required.");
      }

      const pubKeyData = await parsePublicKey(pubKeyInput);
      const modulus = BigInt(pubKeyData.n);
      const keyBits = modulus.toString(2).length;
      const keyBytes = Math.ceil(keyBits / 8);
      const maxSegmentBytes = useOAEP ? keyBytes - 66 : keyBytes - 1;

      if (maxSegmentBytes <= 0) {
        throw new Error("Key size is too small for the selected encryption mode.");
      }

      const segments = segmentMessage(message, maxSegmentBytes);
      const encryptedSegments: string[] = [];
      const pubJwk = useOAEP ? dictToPubJwk(pubKeyData.n, pubKeyData.e) : null;

      for (const segment of segments) {
        encryptedSegments.push(
          useOAEP && pubJwk
            ? await encryptSegmentOAEP(segment, pubJwk)
            : encryptSegmentTextbook(segment, pubKeyData.n, pubKeyData.e)
        );
      }

      const result: EncryptedPayload = {
        segments: encryptedSegments,
        oaep: useOAEP,
        num_segments: segments.length,
        key_bits: keyBits,
        message_sha256: await sha256(message),
        timestamp: new Date().toISOString(),
      };

      setOutput(result);
      addHistory({
        type: "Encrypt",
        details: {
          message,
          output: `Encrypted JSON (${segments.length} segment${segments.length === 1 ? "" : "s"})`,
          keyName: selectedWalletKey?.name,
          status: "Success",
        },
      });
      toast.success({
        title: "Message encrypted",
        description: `Created ${segments.length} encrypted segment${segments.length === 1 ? "" : "s"}.`,
      });
    } catch (error) {
      const messageText =
        error instanceof Error ? error.message : "The message could not be encrypted.";
      setError(messageText);
      addHistory({
        type: "Encrypt",
        details: { status: "Error", message: messageText },
      });
    } finally {
      setLoading(false);
    }
  };

  const handleCopy = async () => {
    if (!outputJson) {
      return;
    }

    try {
      await navigator.clipboard.writeText(outputJson);
      setCopied(true);
      window.setTimeout(() => setCopied(false), 2000);
      toast.success({
        title: "Encrypted payload copied",
        description: "The JSON payload is ready to paste into the Decrypt tab or share safely.",
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
    setPubKeyInput("");
    setMessage("");
    setOutput(null);
    setError(null);
    setCopied(false);
    setUseOAEP(true);
  };

  return (
    <div className="space-y-6">
      <FadeIn className="grid gap-6 xl:grid-cols-[minmax(0,1fr)_380px]">
        <div className="space-y-6">
          <Card className="px-5 py-6">
            <div className="flex flex-col gap-4 border-b border-white/10 pb-4 sm:flex-row sm:items-start sm:justify-between">
              <div>
                <p className="text-[11px] font-semibold uppercase tracking-[0.28em] text-cyan-200/70">
                  Recipient setup
                </p>
                <h2 className="mt-2 flex items-center gap-2 text-2xl font-semibold tracking-tight text-white">
                  <Lock className="h-5 w-5 text-cyan-300" />
                  Public key
                </h2>
                <p className="mt-2 text-sm leading-7 text-slate-400">
                  Load a recipient public key from your wallet, a PEM file, or raw JSON.
                </p>
              </div>
              <FileUpload
                onFileSelect={(data) => {
                  setPubKeyInput(data);
                  setSelectedWalletKeyId("");
                }}
                label="Load JSON or PEM"
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
                      setPubKeyInput(JSON.stringify(key.keys.public, null, 2));
                    } else {
                      setSelectedWalletKeyId("");
                      setPubKeyInput("");
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
                <div className="rounded-[26px] border border-emerald-500/20 bg-emerald-500/10 px-5 py-5">
                  <p className="text-[11px] font-semibold uppercase tracking-[0.26em] text-emerald-200/80">
                    Using wallet identity
                  </p>
                  <h3 className="mt-2 text-xl font-semibold tracking-tight text-white">
                    {selectedWalletKey.name}
                  </h3>
                  <p className="mt-2 text-sm leading-6 text-emerald-100/80">
                    The recipient public key is loaded and ready. Switch to raw mode if you want
                    to inspect or edit the JSON directly.
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
                  value={pubKeyInput}
                  onChange={(event) => {
                    setPubKeyInput(event.target.value);
                    setSelectedWalletKeyId("");
                  }}
                  placeholder="Paste public key JSON or PEM..."
                  className="field-area min-h-[220px]"
                />
              )}
            </div>
          </Card>

          <Card className="px-5 py-6">
            <div className="flex flex-col gap-4 border-b border-white/10 pb-4 sm:flex-row sm:items-start sm:justify-between">
              <div>
                <p className="text-[11px] font-semibold uppercase tracking-[0.28em] text-cyan-200/70">
                  Plaintext
                </p>
                <h2 className="mt-2 flex items-center gap-2 text-2xl font-semibold tracking-tight text-white">
                  <FileJson className="h-5 w-5 text-cyan-300" />
                  Message
                </h2>
                <p className="mt-2 text-sm leading-7 text-slate-400">
                  Enter the content you want to segment and encrypt.
                </p>
              </div>
              <FileUpload onFileSelect={setMessage} label="Load text" accept=".txt,.json,.md" />
            </div>

            <textarea
              value={message}
              onChange={(event) => setMessage(event.target.value)}
              placeholder="Type the message you want to encrypt..."
              className="field-area mt-5 min-h-[220px] text-sm"
            />
          </Card>
        </div>

        <div className="space-y-6">
          <Card className="px-5 py-6">
            <div className="flex items-start justify-between gap-4">
              <div>
                <p className="text-[11px] font-semibold uppercase tracking-[0.28em] text-cyan-200/70">
                  Encryption mode
                </p>
                <h2 className="mt-2 text-2xl font-semibold tracking-tight text-white">Options</h2>
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

            <div className="mt-5 grid gap-3">
              <button
                type="button"
                onClick={() => setUseOAEP(true)}
                className={`rounded-[24px] border px-4 py-4 text-left transition ${
                  useOAEP
                    ? "border-cyan-400/30 bg-cyan-400/10 text-white"
                    : "border-white/10 bg-white/5 text-slate-300 hover:bg-white/10"
                }`}
              >
                <p className="text-sm font-semibold">OAEP padding</p>
                <p className="mt-2 text-sm leading-6 text-slate-400">
                  Recommended. Modern, randomized RSA encryption with better real-world safety.
                </p>
              </button>
              <button
                type="button"
                onClick={() => setUseOAEP(false)}
                className={`rounded-[24px] border px-4 py-4 text-left transition ${
                  !useOAEP
                    ? "border-amber-400/30 bg-amber-500/10 text-white"
                    : "border-white/10 bg-white/5 text-slate-300 hover:bg-white/10"
                }`}
              >
                <p className="text-sm font-semibold">Textbook RSA</p>
                <p className="mt-2 text-sm leading-6 text-slate-400">
                  Educational only. Raw modular arithmetic without secure padding.
                </p>
              </button>
            </div>

            {!useOAEP && (
              <div className="mt-4 rounded-[22px] border border-amber-500/20 bg-amber-500/10 px-4 py-4 text-sm text-amber-100">
                <div className="flex items-start gap-3">
                  <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0" />
                  <p>
                    Textbook RSA is intentionally insecure and is included only to demonstrate how
                    raw RSA behaves before padding is introduced.
                  </p>
                </div>
              </div>
            )}

            {error && (
              <div className="mt-4 rounded-[22px] border border-rose-500/20 bg-rose-500/10 px-4 py-4 text-sm text-rose-100">
                {error}
              </div>
            )}

            <NeonButton
              onClick={handleEncrypt}
              disabled={loading || !pubKeyInput.trim() || !message.trim()}
              className="mt-6 w-full"
              size="lg"
            >
              {loading ? "Encrypting..." : "Encrypt message"}
            </NeonButton>
          </Card>

          <Card className="px-5 py-6">
            <div className="flex items-start justify-between gap-3">
              <div>
                <p className="text-[11px] font-semibold uppercase tracking-[0.28em] text-cyan-200/70">
                  Output
                </p>
                <h2 className="mt-2 text-2xl font-semibold tracking-tight text-white">
                  Encrypted payload
                </h2>
              </div>
              {output && (
                <button
                  type="button"
                  onClick={handleCopy}
                  className="icon-btn"
                  aria-label="Copy encrypted payload JSON"
                >
                  {copied ? (
                    <Check className="h-4 w-4 text-emerald-300" />
                  ) : (
                    <Copy className="h-4 w-4" />
                  )}
                </button>
              )}
            </div>

            {output ? (
              <>
                <div className="mt-5 grid gap-3 sm:grid-cols-3">
                  <div className="metric-tile">
                    <p className="text-[11px] uppercase tracking-[0.24em] text-slate-500">
                      Segments
                    </p>
                    <p className="mt-2 text-xl font-semibold text-white">{output.num_segments}</p>
                  </div>
                  <div className="metric-tile">
                    <p className="text-[11px] uppercase tracking-[0.24em] text-slate-500">
                      Mode
                    </p>
                    <p className="mt-2 text-xl font-semibold text-white">
                      {output.oaep ? "OAEP" : "Textbook"}
                    </p>
                  </div>
                  <div className="metric-tile">
                    <p className="text-[11px] uppercase tracking-[0.24em] text-slate-500">
                      Key size
                    </p>
                    <p className="mt-2 text-xl font-semibold text-white">{output.key_bits} bits</p>
                  </div>
                </div>

                <pre className="code-block mt-5 max-h-[320px] text-emerald-50/80">{outputJson}</pre>

                <NeonButton
                  variant="secondary"
                  onClick={() =>
                    downloadTextFile(
                      `encrypted-message-${new Date().toISOString().replace(/[:.]/g, "-")}.json`,
                      outputJson,
                      "application/json"
                    )
                  }
                  className="mt-4 w-full"
                >
                  <Download className="h-4 w-4" />
                  Download JSON
                </NeonButton>
              </>
            ) : (
              <div className="mt-5 rounded-[26px] border border-dashed border-white/10 bg-white/5 px-5 py-10 text-center">
                <p className="text-lg font-semibold text-white">Nothing encrypted yet</p>
                <p className="mt-2 text-sm leading-6 text-slate-400">
                  Once you encrypt a message, the segmented payload, hash, and mode metadata will
                  appear here.
                </p>
              </div>
            )}
          </Card>
        </div>
      </FadeIn>
    </div>
  );
}
