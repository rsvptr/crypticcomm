"use client";

import { useEffect, useMemo, useState } from "react";
import { Check, Copy, Download, Eye, EyeOff, RefreshCw, Save } from "lucide-react";
import { generateKeyName, generateRSAKey, keyFingerprint, RSAKeyDict } from "@/lib/rsa";
import { downloadTextFile, safeFileBaseName } from "@/lib/download";
import { useToast } from "@/components/ToastContext";
import { useWallet } from "@/components/WalletContext";
import {
  Button,
  Card,
  CardBody,
  CardHeader,
  FadeIn,
  IconButton,
  SegmentedControl,
  StaggerGroup,
  StaggerItem,
} from "@/components/ui/Motion";
import { useCopy } from "@/components/ui/useCopy";

const KEY_SIZES = [
  { value: 1024, label: "1024-bit", hint: "demos only" },
  { value: 2048, label: "2048-bit", hint: "recommended" },
  { value: 4096, label: "4096-bit", hint: "slower" },
];

export default function KeyGen() {
  const [keySize, setKeySize] = useState(2048);
  const [keys, setKeys] = useState<RSAKeyDict | null>(null);
  const [loading, setLoading] = useState(false);
  const [showPrivate, setShowPrivate] = useState(false);
  const [keyName, setKeyName] = useState("");
  const [fingerprint, setFingerprint] = useState<string | null>(null);

  const toast = useToast();
  const { saveKey } = useWallet();
  const { copied, copy } = useCopy();

  useEffect(() => {
    let cancelled = false;
    if (!keys) {
      setFingerprint(null);
      return;
    }
    keyFingerprint(keys.public.n).then((fp) => {
      if (!cancelled) setFingerprint(fp);
    });
    return () => {
      cancelled = true;
    };
  }, [keys]);

  const keyFacts = useMemo(() => {
    if (!keys) {
      return [];
    }

    const modulus = BigInt(keys.public.n);
    const keyBits = modulus.toString(2).length;
    const keyBytes = Math.ceil(keyBits / 8);
    const oaepCapacity = Math.max(keyBytes - 66, 0);

    return [
      { label: "Key size", value: `${keyBits} bits` },
      { label: "Public exponent", value: keys.public.e },
      { label: "OAEP capacity", value: `${oaepCapacity} bytes per segment` },
      { label: "Fingerprint", value: fingerprint ?? "computing" },
    ];
  }, [keys, fingerprint]);

  const handleCopy = async (text: string, tag: string) => {
    const ok = await copy(text, tag);
    if (!ok) {
      toast.error({
        title: "Copy failed",
        description: "The browser blocked clipboard access.",
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
        title: "Key pair generated",
        description: `${generatedName} is ready to export or save.`,
      });
    } catch (error) {
      toast.error({
        title: "Key generation failed",
        description:
          error instanceof Error
            ? error.message
            : "The browser could not generate an RSA key pair.",
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
        description: `${keyName} now shows up in every tool's identity picker.`,
      });
    } catch (error) {
      toast.error({
        title: "Could not save the key",
        description:
          error instanceof Error
            ? error.message
            : "Unlock the wallet from the header first, then try again.",
      });
    }
  };

  const handleDownloadJson = (data: object, suffix: string) => {
    const filename = `${safeFileBaseName(keyName || "crypticcomm")}_${suffix}.json`;
    downloadTextFile(filename, JSON.stringify(data, null, 2), "application/json");
  };

  const handleDownloadPem = (pem: string, suffix: string) => {
    const filename = `${safeFileBaseName(keyName || "crypticcomm")}_${suffix}.pem`;
    downloadTextFile(filename, pem, "text/plain");
  };

  return (
    <div className="space-y-4">
      <FadeIn>
        <Card>
          <CardBody>
            <div className="flex flex-col gap-4 sm:flex-row sm:items-end">
              <div className="flex-1">
                <span className="field-label">Key size</span>
                <SegmentedControl
                  label="Key size"
                  options={KEY_SIZES}
                  value={keySize}
                  onChange={setKeySize}
                />
              </div>
              <Button
                onClick={handleGenerate}
                disabled={loading}
                size="lg"
                className="w-full sm:w-auto"
              >
                {loading ? (
                  <>
                    <RefreshCw className="h-4 w-4 animate-spin" />
                    Generating
                  </>
                ) : (
                  "Generate key pair"
                )}
              </Button>
            </div>
            <p className="mt-3 text-[13px] leading-5 text-zinc-500">
              Keys are generated with the Web Crypto API and exist only on this page until you
              export them or save them to the wallet.
            </p>
          </CardBody>
        </Card>
      </FadeIn>

      {keys && (
        <StaggerGroup key={keys.public.n} className="space-y-4">
          <StaggerItem>
            <Card>
              <CardBody>
                <div className="flex flex-col gap-4 md:flex-row md:items-center md:justify-between">
                  <div className="min-w-0">
                    <p className="text-[13px] text-zinc-500">Generated identity</p>
                    <h2 className="mt-0.5 truncate font-mono text-lg font-medium text-zinc-100">
                      {keyName}
                    </h2>
                  </div>
                  <Button variant="secondary" onClick={handleSaveToWallet}>
                    <Save className="h-4 w-4" />
                    Save to wallet
                  </Button>
                </div>
                <dl className="mt-4 grid gap-3 border-t border-white/[0.06] pt-4 sm:grid-cols-2 lg:grid-cols-4">
                  {keyFacts.map((fact) => (
                    <div key={fact.label} className="min-w-0">
                      <dt className="text-xs text-zinc-500">{fact.label}</dt>
                      <dd
                        title={fact.value}
                        className="mt-0.5 truncate font-mono text-sm text-zinc-200 [font-variant-numeric:tabular-nums]"
                      >
                        {fact.value}
                      </dd>
                    </div>
                  ))}
                </dl>
              </CardBody>
            </Card>
          </StaggerItem>

          <StaggerItem className="grid grid-cols-1 gap-4 lg:grid-cols-2">
            <Card>
              <CardHeader
                title="Public key"
                description="Share this freely. Others use it to encrypt messages to you or check your signatures."
                actions={
                  <>
                    <IconButton
                      label="Copy public key JSON"
                      onClick={() => handleCopy(JSON.stringify(keys.public, null, 2), "public")}
                    >
                      {copied === "public" ? (
                        <Check className="h-4 w-4 animate-pop text-emerald-400" />
                      ) : (
                        <Copy className="h-4 w-4" />
                      )}
                    </IconButton>
                    <IconButton
                      label="Download public key JSON"
                      onClick={() => handleDownloadJson(keys.public, "public")}
                    >
                      <Download className="h-4 w-4" />
                    </IconButton>
                    {keys.public.pem && (
                      <IconButton
                        label="Download public key PEM"
                        onClick={() => handleDownloadPem(keys.public.pem as string, "public")}
                      >
                        <span className="text-[10px] font-semibold tracking-wide">PEM</span>
                      </IconButton>
                    )}
                  </>
                }
              />
              <CardBody>
                <pre className="code-block max-h-80">
                  {JSON.stringify(keys.public, null, 2)}
                </pre>
              </CardBody>
            </Card>

            <Card>
              <CardHeader
                title="Private key"
                description="Keep this one to yourself. Hidden by default so it stays safe on a shared screen."
                actions={
                  <>
                    <IconButton
                      label={showPrivate ? "Hide private key" : "Show private key"}
                      onClick={() => setShowPrivate((current) => !current)}
                    >
                      {showPrivate ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
                    </IconButton>
                    <IconButton
                      label="Copy private key JSON"
                      onClick={() => handleCopy(JSON.stringify(keys.private, null, 2), "private")}
                    >
                      {copied === "private" ? (
                        <Check className="h-4 w-4 animate-pop text-emerald-400" />
                      ) : (
                        <Copy className="h-4 w-4" />
                      )}
                    </IconButton>
                    <IconButton
                      label="Download private key JSON"
                      onClick={() => handleDownloadJson(keys.private, "private")}
                    >
                      <Download className="h-4 w-4" />
                    </IconButton>
                    {keys.private.pem && (
                      <IconButton
                        label="Download private key PEM"
                        onClick={() => handleDownloadPem(keys.private.pem as string, "private")}
                      >
                        <span className="text-[10px] font-semibold tracking-wide">PEM</span>
                      </IconButton>
                    )}
                  </>
                }
              />
              <CardBody>
                <div className="relative overflow-hidden rounded-lg">
                  <pre
                    aria-hidden={!showPrivate}
                    className={`code-block max-h-80 transition duration-200 ${
                      showPrivate ? "" : "select-none opacity-60 blur-sm"
                    }`}
                  >
                    {JSON.stringify(keys.private, null, 2)}
                  </pre>
                  {!showPrivate && (
                    <button
                      type="button"
                      onClick={() => setShowPrivate(true)}
                      className="absolute inset-0 flex items-center justify-center rounded-lg bg-surface-inset/60 transition-colors duration-150 hover:bg-surface-inset/40"
                    >
                      <span className="inline-flex items-center gap-2 rounded-lg border border-white/10 bg-surface px-3 py-1.5 text-[13px] font-medium text-zinc-300">
                        <Eye className="h-3.5 w-3.5" />
                        Reveal private key
                      </span>
                    </button>
                  )}
                </div>
              </CardBody>
            </Card>
          </StaggerItem>
        </StaggerGroup>
      )}
    </div>
  );
}
