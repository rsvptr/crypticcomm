"use client";

import { useMemo, useState } from "react";
import {
  Check,
  Copy,
  Download,
  FileJson,
  RefreshCcw,
  Unlock,
} from "lucide-react";
import {
  decryptSegmentOAEP,
  decryptSegmentTextbook,
  dictToPrivJwk,
  pemToRSAKeyDict,
  sha256,
} from "@/lib/rsa";
import { useHistory } from "@/components/HistoryContext";
import { useToast } from "@/components/ToastContext";
import { useWallet } from "@/components/WalletContext";
import { Card, FadeIn, FileUpload, NeonButton } from "@/components/ui/Motion";

interface EncryptedPayload {
  segments: string[];
  oaep: boolean;
}

interface DecryptStats {
  total: number;
  failed: number;
  sha256: string;
}

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

export default function Decrypt() {
  const { keys } = useWallet();
  const { addHistory } = useHistory();
  const toast = useToast();

  const [privKeyInput, setPrivKeyInput] = useState("");
  const [encryptedInput, setEncryptedInput] = useState("");
  const [loading, setLoading] = useState(false);
  const [output, setOutput] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [stats, setStats] = useState<DecryptStats | null>(null);
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
      typeof (parsed as ParsedPrivateKey).n !== "string" ||
      typeof (parsed as ParsedPrivateKey).d !== "string"
    ) {
      throw new Error("Private key JSON must include string values for n and d.");
    }

    return parsed as ParsedPrivateKey;
  };

  const parseEncryptedPayload = (rawInput: string): EncryptedPayload => {
    let parsed: unknown;
    try {
      parsed = JSON.parse(rawInput);
    } catch {
      throw new Error("Encrypted payload must be valid JSON.");
    }

    if (
      !parsed ||
      typeof parsed !== "object" ||
      !Array.isArray((parsed as EncryptedPayload).segments) ||
      typeof (parsed as EncryptedPayload).oaep !== "boolean"
    ) {
      throw new Error("Encrypted payload JSON must include segments[] and oaep.");
    }

    return parsed as EncryptedPayload;
  };

  const handleDecrypt = async () => {
    setError(null);
    setLoading(true);
    setOutput("");
    setStats(null);
    setCopied(false);

    try {
      if (!privKeyInput.trim() || !encryptedInput.trim()) {
        throw new Error("Private key and encrypted payload are required.");
      }

      const privKeyData = await parsePrivateKey(privKeyInput);
      const encryptedPayload = parseEncryptedPayload(encryptedInput);

      let privJwk: JsonWebKey | undefined;
      if (encryptedPayload.oaep) {
        privJwk = dictToPrivJwk(privKeyData);
      }

      const decryptedSegments: string[] = [];
      let failed = 0;

      for (const segment of encryptedPayload.segments) {
        const plaintext = encryptedPayload.oaep && privJwk
          ? await decryptSegmentOAEP(segment, privJwk)
          : decryptSegmentTextbook(segment, privKeyData.n, privKeyData.d);

        if (plaintext.startsWith("[Decryption error")) {
          failed += 1;
        }

        decryptedSegments.push(plaintext);
      }

      const finalMessage = decryptedSegments.join("");
      setOutput(finalMessage);
      setStats({
        total: encryptedPayload.segments.length,
        failed,
        sha256: await sha256(finalMessage),
      });

      addHistory({
        type: "Decrypt",
        details: {
          message: `Encrypted JSON (${encryptedPayload.segments.length} segment${
            encryptedPayload.segments.length === 1 ? "" : "s"
          })`,
          output: finalMessage,
          keyName: selectedWalletKey?.name,
          status: failed > 0 ? "Partial Failure" : "Success",
        },
      });

      toast.success({
        title: failed > 0 ? "Message partially decrypted" : "Message decrypted",
        description:
          failed > 0
            ? `${failed} segment${failed === 1 ? "" : "s"} could not be recovered cleanly.`
            : "The plaintext has been reconstructed successfully.",
      });
    } catch (error) {
      const messageText =
        error instanceof Error ? error.message : "The payload could not be decrypted.";
      setError(messageText);
      addHistory({
        type: "Decrypt",
        details: { status: "Error", message: messageText },
      });
    } finally {
      setLoading(false);
    }
  };

  const handleCopy = async () => {
    if (!output) {
      return;
    }

    try {
      await navigator.clipboard.writeText(output);
      setCopied(true);
      window.setTimeout(() => setCopied(false), 2000);
      toast.success({
        title: "Plaintext copied",
        description: "The recovered message is now on your clipboard.",
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
    setEncryptedInput("");
    setOutput("");
    setError(null);
    setStats(null);
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
                  Recipient identity
                </p>
                <h2 className="mt-2 flex items-center gap-2 text-2xl font-semibold tracking-tight text-white">
                  <Unlock className="h-5 w-5 text-cyan-300" />
                  Private key
                </h2>
                <p className="mt-2 text-sm leading-7 text-slate-400">
                  Load the matching private key to recover the plaintext from the encrypted JSON.
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
                    The matching private key is loaded in memory. Switch to raw mode if you need to
                    inspect or edit the key manually.
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
                  Ciphertext
                </p>
                <h2 className="mt-2 flex items-center gap-2 text-2xl font-semibold tracking-tight text-white">
                  <FileJson className="h-5 w-5 text-cyan-300" />
                  Encrypted payload
                </h2>
                <p className="mt-2 text-sm leading-7 text-slate-400">
                  Paste the encryption result JSON with segments and mode metadata.
                </p>
              </div>
              <FileUpload onFileSelect={setEncryptedInput} label="Load JSON" accept=".json,.txt" />
            </div>

            <textarea
              value={encryptedInput}
              onChange={(event) => setEncryptedInput(event.target.value)}
              placeholder="Paste encrypted JSON..."
              className="field-area mt-5 min-h-[220px]"
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
                  Recover plaintext
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
              CrypticComm will reconstruct each segment in order, then join them back into a single
              message.
            </p>

            {error && (
              <div className="mt-4 rounded-[22px] border border-rose-500/20 bg-rose-500/10 px-4 py-4 text-sm text-rose-100">
                {error}
              </div>
            )}

            <NeonButton
              onClick={handleDecrypt}
              disabled={loading || !privKeyInput.trim() || !encryptedInput.trim()}
              className="mt-6 w-full"
              size="lg"
            >
              {loading ? "Decrypting..." : "Decrypt message"}
            </NeonButton>
          </Card>

          <Card className="px-5 py-6">
            <div className="flex items-start justify-between gap-3">
              <div>
                <p className="text-[11px] font-semibold uppercase tracking-[0.28em] text-cyan-200/70">
                  Output
                </p>
                <h2 className="mt-2 text-2xl font-semibold tracking-tight text-white">
                  Decrypted plaintext
                </h2>
              </div>
              {output && (
                <button
                  type="button"
                  onClick={handleCopy}
                  className="icon-btn"
                  aria-label="Copy decrypted plaintext"
                >
                  {copied ? (
                    <Check className="h-4 w-4 text-emerald-300" />
                  ) : (
                    <Copy className="h-4 w-4" />
                  )}
                </button>
              )}
            </div>

            {stats && (
              <div className="mt-5 grid gap-3 sm:grid-cols-3">
                <div className="metric-tile">
                  <p className="text-[11px] uppercase tracking-[0.24em] text-slate-500">
                    Segments
                  </p>
                  <p className="mt-2 text-xl font-semibold text-white">{stats.total}</p>
                </div>
                <div className="metric-tile">
                  <p className="text-[11px] uppercase tracking-[0.24em] text-slate-500">
                    Failures
                  </p>
                  <p className="mt-2 text-xl font-semibold text-white">{stats.failed}</p>
                </div>
                <div className="metric-tile">
                  <p className="text-[11px] uppercase tracking-[0.24em] text-slate-500">
                    Result
                  </p>
                  <p className="mt-2 text-xl font-semibold text-white">
                    {stats.failed > 0 ? "Partial" : "Clean"}
                  </p>
                </div>
              </div>
            )}

            <textarea
              readOnly
              value={output}
              placeholder="Decrypted text will appear here..."
              className="field-area mt-5 min-h-[260px] resize-none text-sm text-indigo-100"
            />

            {output && (
              <NeonButton
                variant="secondary"
                onClick={() =>
                  downloadTextFile(
                    `decrypted-message-${new Date().toISOString().replace(/[:.]/g, "-")}.txt`,
                    output,
                    "text/plain"
                  )
                }
                className="mt-4 w-full"
              >
                <Download className="h-4 w-4" />
                Download plaintext
              </NeonButton>
            )}
          </Card>
        </div>
      </FadeIn>
    </div>
  );
}
