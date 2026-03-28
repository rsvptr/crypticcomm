"use client";

import { useMemo, useState } from "react";
import {
  CheckCircle2,
  FileSignature,
  Fingerprint,
  RefreshCcw,
  ShieldCheck,
  XCircle,
} from "lucide-react";
import { dictToPubJwk, pemToRSAKeyDict, verifySignature } from "@/lib/rsa";
import { useHistory } from "@/components/HistoryContext";
import { useToast } from "@/components/ToastContext";
import { useWallet } from "@/components/WalletContext";
import { Card, FadeIn, FileUpload, NeonButton } from "@/components/ui/Motion";

interface ParsedPublicKey {
  n: string;
  e: string;
}

export default function Verify() {
  const { keys } = useWallet();
  const { addHistory } = useHistory();
  const toast = useToast();

  const [pubKeyInput, setPubKeyInput] = useState("");
  const [message, setMessage] = useState("");
  const [signature, setSignature] = useState("");
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<boolean | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [selectedWalletKeyId, setSelectedWalletKeyId] = useState("");

  const selectedWalletKey = useMemo(
    () => keys.find((key) => key.id === selectedWalletKeyId),
    [keys, selectedWalletKeyId]
  );

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

  const handleVerify = async () => {
    setError(null);
    setLoading(true);
    setResult(null);

    try {
      if (!pubKeyInput.trim() || !message.trim() || !signature.trim()) {
        throw new Error("Public key, message, and signature are required.");
      }

      const pubKeyData = await parsePublicKey(pubKeyInput);
      const pubJwk = dictToPubJwk(pubKeyData.n, pubKeyData.e);
      const isValid = await verifySignature(message, signature.trim(), pubJwk);

      setResult(isValid);
      addHistory({
        type: "Verify",
        details: {
          message,
          output: `Signature was ${isValid ? "valid" : "invalid"}.`,
          keyName: selectedWalletKey?.name,
          status: isValid ? "Success" : "Invalid",
        },
      });
      toast[isValid ? "success" : "info"]({
        title: isValid ? "Signature verified" : "Signature did not match",
        description: isValid
          ? "The message and signer public key match this signature."
          : "The signature, message, or key does not line up.",
      });
    } catch (error) {
      const messageText =
        error instanceof Error ? error.message : "The signature could not be verified.";
      setError(messageText);
      addHistory({
        type: "Verify",
        details: { status: "Error", message: messageText },
      });
    } finally {
      setLoading(false);
    }
  };

  const clearAll = () => {
    setSelectedWalletKeyId("");
    setPubKeyInput("");
    setMessage("");
    setSignature("");
    setResult(null);
    setError(null);
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
                  <ShieldCheck className="h-5 w-5 text-cyan-300" />
                  Public key
                </h2>
                <p className="mt-2 text-sm leading-7 text-slate-400">
                  Load the signer public key used to check the signature.
                </p>
              </div>
              <FileUpload
                onFileSelect={(data) => {
                  setPubKeyInput(data);
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
                    The signer public key is loaded and ready for verification.
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
                  className="field-area min-h-[200px]"
                />
              )}
            </div>
          </Card>

          <Card className="px-5 py-6">
            <div className="flex flex-col gap-4 border-b border-white/10 pb-4 sm:flex-row sm:items-start sm:justify-between">
              <div>
                <p className="text-[11px] font-semibold uppercase tracking-[0.28em] text-cyan-200/70">
                  Original content
                </p>
                <h2 className="mt-2 flex items-center gap-2 text-2xl font-semibold tracking-tight text-white">
                  <FileSignature className="h-5 w-5 text-cyan-300" />
                  Message
                </h2>
                <p className="mt-2 text-sm leading-7 text-slate-400">
                  The exact message used during signing. Any edit here will invalidate the check.
                </p>
              </div>
              <FileUpload onFileSelect={setMessage} label="Load text" accept=".txt,.md" />
            </div>

            <textarea
              value={message}
              onChange={(event) => setMessage(event.target.value)}
              placeholder="Paste the original message..."
              className="field-area mt-5 min-h-[200px] text-sm"
            />
          </Card>

          <Card className="px-5 py-6">
            <div className="flex flex-col gap-4 border-b border-white/10 pb-4 sm:flex-row sm:items-start sm:justify-between">
              <div>
                <p className="text-[11px] font-semibold uppercase tracking-[0.28em] text-cyan-200/70">
                  Signature
                </p>
                <h2 className="mt-2 flex items-center gap-2 text-2xl font-semibold tracking-tight text-white">
                  <Fingerprint className="h-5 w-5 text-cyan-300" />
                  Hex proof
                </h2>
                <p className="mt-2 text-sm leading-7 text-slate-400">
                  Paste the hexadecimal RSA-PSS signature you want to validate.
                </p>
              </div>
              <FileUpload onFileSelect={setSignature} label="Load text" accept=".txt" />
            </div>

            <textarea
              value={signature}
              onChange={(event) => setSignature(event.target.value)}
              placeholder="Paste the hex signature..."
              className="field-area mt-5 min-h-[160px]"
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
                  Verify signature
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
              Verification compares the message, the signature, and the signer public key in one
              check.
            </p>

            {error && (
              <div className="mt-4 rounded-[22px] border border-rose-500/20 bg-rose-500/10 px-4 py-4 text-sm text-rose-100">
                {error}
              </div>
            )}

            <NeonButton
              onClick={handleVerify}
              disabled={loading || !pubKeyInput.trim() || !message.trim() || !signature.trim()}
              className="mt-6 w-full"
              size="lg"
            >
              {loading ? "Verifying..." : "Verify signature"}
            </NeonButton>
          </Card>

          <Card className="px-5 py-6">
            <p className="text-[11px] font-semibold uppercase tracking-[0.28em] text-cyan-200/70">
              Result
            </p>
            <h2 className="mt-2 text-2xl font-semibold tracking-tight text-white">
              Verification status
            </h2>

            {result === null ? (
              <div className="mt-5 rounded-[26px] border border-dashed border-white/10 bg-white/5 px-5 py-10 text-center">
                <p className="text-lg font-semibold text-white">Waiting for a verification run</p>
                <p className="mt-2 text-sm leading-6 text-slate-400">
                  Run the check to see whether this signature matches the supplied key and message.
                </p>
              </div>
            ) : result ? (
              <div className="mt-5 rounded-[26px] border border-emerald-500/30 bg-emerald-500/10 px-5 py-8 text-center">
                <div className="mx-auto flex h-16 w-16 items-center justify-center rounded-full border border-emerald-400/30 bg-emerald-400/20 text-emerald-100">
                  <CheckCircle2 className="h-8 w-8" />
                </div>
                <h3 className="mt-5 text-2xl font-semibold tracking-tight text-white">
                  Signature is valid
                </h3>
                <p className="mt-3 text-sm leading-7 text-emerald-100/85">
                  The message, signature, and public key all line up. This content has not been
                  altered relative to the supplied proof.
                </p>
              </div>
            ) : (
              <div className="mt-5 rounded-[26px] border border-rose-500/30 bg-rose-500/10 px-5 py-8 text-center">
                <div className="mx-auto flex h-16 w-16 items-center justify-center rounded-full border border-rose-400/30 bg-rose-400/20 text-rose-100">
                  <XCircle className="h-8 w-8" />
                </div>
                <h3 className="mt-5 text-2xl font-semibold tracking-tight text-white">
                  Signature is invalid
                </h3>
                <p className="mt-3 text-sm leading-7 text-rose-100/85">
                  The signature does not match this message and public key combination. Either the
                  content changed, the wrong key was supplied, or the signature was corrupted.
                </p>
              </div>
            )}
          </Card>
        </div>
      </FadeIn>
    </div>
  );
}
