"use client";

import { useMemo, useState } from "react";
import {
  Check,
  Copy,
  Download,
  Eye,
  EyeOff,
  RefreshCw,
  Save,
} from "lucide-react";
import { generateKeyName, generateRSAKey, RSAKeyDict } from "@/lib/rsa";
import { useToast } from "@/components/ToastContext";
import { useWallet } from "@/components/WalletContext";
import { Card, FadeIn, NeonButton } from "@/components/ui/Motion";

function safeFileBaseName(name: string) {
  return name.replace(/[^a-zA-Z0-9]+/g, "_").replace(/_+/g, "_");
}

function downloadText(filename: string, content: string, type: string) {
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

export default function KeyGen() {
  const [keySize, setKeySize] = useState(2048);
  const [keys, setKeys] = useState<RSAKeyDict | null>(null);
  const [loading, setLoading] = useState(false);
  const [showPrivate, setShowPrivate] = useState(false);
  const [keyName, setKeyName] = useState("");
  const [copied, setCopied] = useState<string | null>(null);

  const toast = useToast();
  const { saveKey } = useWallet();

  const keyFacts = useMemo(() => {
    if (!keys) {
      return [];
    }

    const modulus = BigInt(keys.public.n);
    const keyBits = modulus.toString(2).length;
    const keyBytes = Math.ceil(keyBits / 8);
    const oaepCapacity = Math.max(keyBytes - 66, 0);

    return [
      { label: "Identity", value: keyName || "Generated" },
      { label: "Key size", value: `${keyBits} bits` },
      { label: "OAEP payload", value: `${oaepCapacity} bytes / segment` },
      { label: "Exports", value: "JSON + PEM" },
    ];
  }, [keyName, keys]);

  const copyToClipboard = async (text: string, type: string) => {
    try {
      await navigator.clipboard.writeText(text);
      setCopied(type);
      window.setTimeout(() => setCopied(null), 2000);
    } catch {
      toast.error({
        title: "Copy failed",
        description: "Clipboard access was blocked by the browser.",
      });
    }
  };

  const handleGenerate = async () => {
    setLoading(true);
    setKeys(null);
    setKeyName("");
    setShowPrivate(false);

    try {
      const generatedKeys = await generateRSAKey(keySize);
      const generatedName = await generateKeyName(generatedKeys.public);
      setKeyName(generatedName);
      setKeys(generatedKeys);
      toast.success({
        title: "Identity generated",
        description: `${generatedName} is ready for export or wallet storage.`,
      });
    } catch (error) {
      toast.error({
        title: "Key generation failed",
        description:
          error instanceof Error
            ? error.message
            : "The browser could not generate the RSA pair.",
      });
    } finally {
      setLoading(false);
    }
  };

  const handleSaveToWallet = async () => {
    if (!keys) {
      return;
    }

    try {
      await saveKey(keys);
      toast.success({
        title: "Saved to wallet",
        description: `${keyName} is now available across the app.`,
      });
    } catch (error) {
      toast.error({
        title: "Could not save key",
        description:
          error instanceof Error
            ? error.message
            : "Unlock your wallet before saving this identity.",
      });
    }
  };

  const handleDownloadJson = (data: object, suffix: string) => {
    const filename = `${safeFileBaseName(keyName || "crypticcomm")}_${suffix}.json`;
    downloadText(filename, JSON.stringify(data, null, 2), "application/json");
  };

  const handleDownloadPem = (pem: string, suffix: string) => {
    const filename = `${safeFileBaseName(keyName || "crypticcomm")}_${suffix}.pem`;
    downloadText(filename, pem, "text/plain");
  };

  return (
    <div className="space-y-6">
      <FadeIn>
        <Card className="overflow-hidden">
          <div className="grid gap-6 lg:grid-cols-[minmax(0,0.9fr)_minmax(0,1.1fr)] lg:items-end">
            <div>
              <p className="text-[11px] font-semibold uppercase tracking-[0.28em] text-cyan-200/70">
                Identity creation
              </p>
              <h2 className="mt-2 text-2xl font-semibold tracking-tight text-white">
                Generate a new RSA key pair
              </h2>
              <p className="mt-3 max-w-xl text-sm leading-6 text-slate-400">
                Choose the key strength that fits your demo or security goal. CrypticComm will
                generate PEM-exportable keys entirely in your browser.
              </p>
            </div>

            <div className="flex flex-col gap-4 sm:flex-row sm:items-end">
              <div className="flex-1">
                <label className="mb-2 block text-sm font-medium text-slate-300">
                  Key strength
                </label>
                <select
                  value={keySize}
                  onChange={(event) => setKeySize(Number(event.target.value))}
                  className="field-input"
                >
                  <option value={1024}>1024-bit · demo only</option>
                  <option value={2048}>2048-bit · standard secure</option>
                  <option value={4096}>4096-bit · heavyweight / slower</option>
                </select>
              </div>

              <NeonButton
                onClick={handleGenerate}
                disabled={loading}
                className="w-full sm:w-auto"
              >
                {loading ? (
                  <>
                    <RefreshCw className="h-4 w-4 animate-spin" />
                    Generating...
                  </>
                ) : (
                  "Generate identity"
                )}
              </NeonButton>
            </div>
          </div>
        </Card>
      </FadeIn>

      {keys && (
        <>
          <FadeIn className="grid gap-4 md:grid-cols-2 xl:grid-cols-4" delay={0.08}>
            {keyFacts.map((fact) => (
              <div key={fact.label} className="metric-tile">
                <p className="text-[11px] uppercase tracking-[0.26em] text-slate-500">
                  {fact.label}
                </p>
                <p className="mt-3 text-lg font-semibold tracking-tight text-white">{fact.value}</p>
              </div>
            ))}
          </FadeIn>

          <FadeIn delay={0.12} className="grid grid-cols-1 gap-6 lg:grid-cols-2">
            <Card className="border-emerald-500/20">
              <div className="mb-4 flex flex-wrap items-start justify-between gap-3">
                <div>
                  <h3 className="text-lg font-semibold text-emerald-300">Public key</h3>
                  <p className="mt-1 text-sm text-slate-400">Safe to share with anyone.</p>
                </div>
                <div className="flex flex-wrap gap-2">
                  <button
                    type="button"
                    onClick={() => copyToClipboard(JSON.stringify(keys.public, null, 2), "public")}
                    className="icon-btn"
                    aria-label="Copy public key JSON"
                  >
                    {copied === "public" ? (
                      <Check className="h-4 w-4 text-emerald-300" />
                    ) : (
                      <Copy className="h-4 w-4" />
                    )}
                  </button>
                  <button
                    type="button"
                    onClick={() => handleDownloadJson(keys.public, "public")}
                    className="icon-btn"
                    aria-label="Download public key JSON"
                  >
                    <Download className="h-4 w-4" />
                  </button>
                  {keys.public.pem && (
                    <button
                      type="button"
                      onClick={() => handleDownloadPem(keys.public.pem as string, "public")}
                      className="icon-btn"
                      aria-label="Download public key PEM"
                    >
                      <span className="text-[11px] font-semibold tracking-[0.18em]">PEM</span>
                    </button>
                  )}
                </div>
              </div>

              <pre className="code-block text-emerald-50/80">
                {JSON.stringify(keys.public, null, 2)}
              </pre>
            </Card>

            <Card className="border-rose-500/20">
              <div className="mb-4 flex flex-wrap items-start justify-between gap-3">
                <div>
                  <h3 className="text-lg font-semibold text-rose-300">Private key</h3>
                  <p className="mt-1 text-sm text-slate-400">
                    Hidden by default so you can present safely without leaking it on screen.
                  </p>
                </div>
                <div className="flex flex-wrap gap-2">
                  <button
                    type="button"
                    onClick={() => setShowPrivate((current) => !current)}
                    className="icon-btn"
                    aria-label={showPrivate ? "Hide private key" : "Show private key"}
                  >
                    {showPrivate ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
                  </button>
                  <button
                    type="button"
                    onClick={() => copyToClipboard(JSON.stringify(keys.private, null, 2), "private")}
                    className="icon-btn"
                    aria-label="Copy private key JSON"
                  >
                    {copied === "private" ? (
                      <Check className="h-4 w-4 text-emerald-300" />
                    ) : (
                      <Copy className="h-4 w-4" />
                    )}
                  </button>
                  <button
                    type="button"
                    onClick={() => handleDownloadJson(keys.private, "private")}
                    className="icon-btn"
                    aria-label="Download private key JSON"
                  >
                    <Download className="h-4 w-4" />
                  </button>
                  {keys.private.pem && (
                    <button
                      type="button"
                      onClick={() => handleDownloadPem(keys.private.pem as string, "private")}
                      className="icon-btn"
                      aria-label="Download private key PEM"
                    >
                      <span className="text-[11px] font-semibold tracking-[0.18em]">PEM</span>
                    </button>
                  )}
                </div>
              </div>

              <div className="relative overflow-hidden rounded-[28px] border border-white/10 bg-[#050915]">
                {!showPrivate && (
                  <div className="pointer-events-none absolute inset-0 z-10 flex items-center justify-center bg-[linear-gradient(180deg,rgba(5,9,21,0.15),rgba(5,9,21,0.82))]">
                    <div className="rounded-full border border-white/10 bg-white/10 px-4 py-2 text-xs font-semibold uppercase tracking-[0.24em] text-slate-200">
                      Hidden for privacy
                    </div>
                  </div>
                )}
                <pre
                  className={`code-block max-h-[320px] border-0 text-rose-50/70 transition duration-200 ${
                    showPrivate ? "" : "blur-md select-none opacity-40"
                  }`}
                >
                  {JSON.stringify(keys.private, null, 2)}
                </pre>
              </div>
            </Card>
          </FadeIn>

          <FadeIn delay={0.16} className="flex justify-center">
            <NeonButton
              onClick={handleSaveToWallet}
              variant="secondary"
              className="w-full sm:w-auto"
            >
              <Save className="h-4 w-4" />
              Save to browser wallet
            </NeonButton>
          </FadeIn>
        </>
      )}
    </div>
  );
}
