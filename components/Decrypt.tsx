"use client";

import { useEffect, useMemo, useState } from "react";
import { motion } from "framer-motion";
import { Check, Copy, Download, RotateCcw } from "lucide-react";
import {
  decryptSegmentOAEP,
  decryptSegmentTextbook,
  dictToPrivJwk,
  parsePrivateKeyInput,
  sha256,
} from "@/lib/rsa";
import { downloadTextFile, timestampedFilename } from "@/lib/download";
import { useHistory } from "@/components/HistoryContext";
import { useToast } from "@/components/ToastContext";
import { useWallet } from "@/components/WalletContext";
import { useWorkbench } from "@/components/WorkbenchContext";
import {
  Button,
  Card,
  CardBody,
  CardHeader,
  FadeIn,
  FileUpload,
  IconButton,
  PopIn,
  SPRING_POP,
} from "@/components/ui/Motion";
import {
  KeyStatusLine,
  SelectedIdentityNotice,
  useParsedKeyInfo,
  WalletKeyPicker,
} from "@/components/ui/KeyInput";
import { useCopy } from "@/components/ui/useCopy";

interface EncryptedPayload {
  segments: string[];
  oaep: boolean;
  message_sha256?: string;
}

type IntegrityResult = "match" | "mismatch" | "none";

interface DecryptStats {
  total: number;
  failed: number;
  sha256: string;
  integrity: IntegrityResult;
  segmentOk: boolean[];
}

const MAX_SEGMENT_CHIPS = 48;

function parseEncryptedPayload(rawInput: string): EncryptedPayload {
  let parsed: unknown;
  try {
    parsed = JSON.parse(rawInput);
  } catch {
    throw new Error("The encrypted payload has to be valid JSON.");
  }

  if (
    !parsed ||
    typeof parsed !== "object" ||
    !Array.isArray((parsed as EncryptedPayload).segments) ||
    typeof (parsed as EncryptedPayload).oaep !== "boolean"
  ) {
    throw new Error('The payload JSON needs a "segments" array and an "oaep" flag.');
  }

  return parsed as EncryptedPayload;
}

export default function Decrypt() {
  const { keys } = useWallet();
  const { addHistory } = useHistory();
  const { consumeDecryptHandoff } = useWorkbench();
  const toast = useToast();
  const { copied, copy } = useCopy();

  const [privKeyInput, setPrivKeyInput] = useState("");
  const [encryptedInput, setEncryptedInput] = useState("");
  const [loading, setLoading] = useState(false);
  const [output, setOutput] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [stats, setStats] = useState<DecryptStats | null>(null);
  const [selectedWalletKeyId, setSelectedWalletKeyId] = useState("");

  // Pick up a payload handed over from the Encrypt tab.
  useEffect(() => {
    const handoff = consumeDecryptHandoff();
    if (handoff) {
      setEncryptedInput(handoff);
    }
  }, [consumeDecryptHandoff]);

  const selectedWalletKey = useMemo(
    () => keys.find((key) => key.id === selectedWalletKeyId),
    [keys, selectedWalletKeyId]
  );
  const keyInfo = useParsedKeyInfo(privKeyInput, "private");

  // If the selected wallet identity disappears (wallet locked, key deleted),
  // scrub the key material that came from it.
  useEffect(() => {
    if (selectedWalletKeyId && !selectedWalletKey) {
      setSelectedWalletKeyId("");
      setPrivKeyInput("");
    }
  }, [selectedWalletKey, selectedWalletKeyId]);

  const handleDecrypt = async () => {
    setError(null);
    setLoading(true);
    setOutput("");
    setStats(null);

    try {
      if (!privKeyInput.trim() || !encryptedInput.trim()) {
        throw new Error("Load a private key and paste the encrypted payload first.");
      }

      const privKeyData = await parsePrivateKeyInput(privKeyInput);
      const encryptedPayload = parseEncryptedPayload(encryptedInput);

      let privJwk: JsonWebKey | undefined;
      if (encryptedPayload.oaep) {
        privJwk = dictToPrivJwk(privKeyData);
      }

      const decryptedSegments: string[] = [];
      const segmentOk: boolean[] = [];
      let failed = 0;

      for (const segment of encryptedPayload.segments) {
        const plaintext =
          encryptedPayload.oaep && privJwk
            ? await decryptSegmentOAEP(segment, privJwk)
            : decryptSegmentTextbook(segment, privKeyData.n, privKeyData.d);

        const ok = !plaintext.startsWith("[Decryption error");
        if (!ok) {
          failed += 1;
        }

        segmentOk.push(ok);
        decryptedSegments.push(plaintext);
      }

      const finalMessage = decryptedSegments.join("");
      const recoveredHash = await sha256(finalMessage);
      // Payloads from the Encrypt tab carry the hash of the original message,
      // which lets the recipient prove the recovered text is byte-identical.
      const integrity: IntegrityResult = encryptedPayload.message_sha256
        ? encryptedPayload.message_sha256 === recoveredHash
          ? "match"
          : "mismatch"
        : "none";

      setOutput(finalMessage);
      setStats({
        total: encryptedPayload.segments.length,
        failed,
        sha256: recoveredHash,
        integrity,
        segmentOk,
      });

      addHistory({
        type: "Decrypt",
        details: {
          message: `Encrypted payload with ${encryptedPayload.segments.length} segment${
            encryptedPayload.segments.length === 1 ? "" : "s"
          }`,
          output: finalMessage,
          keyName: selectedWalletKey?.name,
          status:
            failed > 0
              ? "Partial Failure"
              : integrity === "mismatch"
                ? "Hash mismatch"
                : "Success",
        },
      });

      if (failed > 0) {
        toast.error({
          title: "Partially decrypted",
          description: `${failed} of ${encryptedPayload.segments.length} segments could not be recovered. Check that the key matches.`,
        });
      } else if (integrity === "mismatch") {
        toast.error({
          title: "Decrypted, but altered",
          description: "The recovered text does not hash to the value stored in the payload.",
        });
      } else {
        toast.success({
          title: "Message decrypted",
          description:
            integrity === "match"
              ? "Every segment recovered, and the hash matches the original."
              : "The plaintext was rebuilt from every segment.",
        });
      }
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

    const ok = await copy(output, "plaintext");
    if (!ok) {
      toast.error({
        title: "Copy failed",
        description: "The browser blocked clipboard access.",
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
  };

  return (
    <FadeIn className="grid gap-4 xl:grid-cols-[minmax(0,1fr)_370px]">
      <div className="space-y-4">
        <Card>
          <CardHeader
            title="Private key"
            description="Only the private key that matches the encryption key can recover the message."
            actions={
              <FileUpload
                onFileSelect={(data) => {
                  setPrivKeyInput(data);
                  setSelectedWalletKeyId("");
                }}
                label="Load JSON or PEM"
                accept=".json,.pem,.txt"
              />
            }
          />
          <CardBody>
            <WalletKeyPicker
              selectedId={selectedWalletKeyId}
              onSelect={(key) => {
                if (key) {
                  setSelectedWalletKeyId(key.id);
                  setPrivKeyInput(JSON.stringify(key.keys.private, null, 2));
                } else {
                  setSelectedWalletKeyId("");
                  setPrivKeyInput("");
                }
              }}
            />
            {selectedWalletKey ? (
              <SelectedIdentityNotice
                name={selectedWalletKey.name}
                detail="Private key loaded from the wallet. It stays in memory on this device."
                onClear={() => setSelectedWalletKeyId("")}
              />
            ) : (
              <textarea
                value={privKeyInput}
                onChange={(event) => {
                  setPrivKeyInput(event.target.value);
                  setSelectedWalletKeyId("");
                }}
                placeholder="Paste a private key as JSON or PEM"
                aria-label="Private key"
                className="field-area min-h-[11rem]"
              />
            )}
            <KeyStatusLine info={keyInfo} kind="private" />
          </CardBody>
        </Card>

        <Card>
          <CardHeader
            title="Encrypted payload"
            description="The JSON produced by the Encrypt tab, segments and mode flag included."
            actions={<FileUpload onFileSelect={setEncryptedInput} label="Load JSON" accept=".json,.txt" />}
          />
          <CardBody>
            <textarea
              value={encryptedInput}
              onChange={(event) => setEncryptedInput(event.target.value)}
              onKeyDown={(event) => {
                if ((event.ctrlKey || event.metaKey) && event.key === "Enter") {
                  event.preventDefault();
                  if (!loading && privKeyInput.trim() && encryptedInput.trim()) {
                    void handleDecrypt();
                  }
                }
              }}
              placeholder="Paste the encrypted JSON payload"
              aria-label="Encrypted payload"
              className="field-area min-h-[11rem]"
            />
          </CardBody>
        </Card>
      </div>

      <div className="space-y-4">
        <Card>
          <CardHeader
            title="Decrypt"
            actions={
              <Button variant="ghost" size="sm" onClick={clearAll}>
                <RotateCcw className="h-3.5 w-3.5" />
                Reset
              </Button>
            }
          />
          <CardBody>
            <p className="text-[13px] leading-5 text-zinc-500">
              Each segment is decrypted on its own and the results are joined in order, so a
              single bad segment doesn&apos;t take the whole message down with it.
            </p>

            {error && (
              <div role="alert" className="notice-danger mt-3">
                {error}
              </div>
            )}

            <Button
              onClick={handleDecrypt}
              disabled={loading || !privKeyInput.trim() || !encryptedInput.trim()}
              className="mt-4 w-full"
              size="lg"
              title="Ctrl+Enter in the payload box also runs this"
            >
              {loading ? "Decrypting" : "Decrypt payload"}
            </Button>
          </CardBody>
        </Card>

        <Card>
          <CardHeader
            title="Recovered plaintext"
            actions={
              output ? (
                <>
                  <IconButton label="Copy plaintext" onClick={handleCopy}>
                    {copied === "plaintext" ? (
                      <Check className="h-4 w-4 animate-pop text-emerald-400" />
                    ) : (
                      <Copy className="h-4 w-4" />
                    )}
                  </IconButton>
                  <IconButton
                    label="Download plaintext"
                    onClick={() =>
                      downloadTextFile(
                        timestampedFilename("decrypted-message", "txt"),
                        output,
                        "text/plain"
                      )
                    }
                  >
                    <Download className="h-4 w-4" />
                  </IconButton>
                </>
              ) : undefined
            }
          />
          <CardBody>
            {stats && (
              <PopIn key={`${stats.sha256}-${stats.total}-${stats.failed}`}>
                <dl className="mb-4 grid grid-cols-2 gap-3 sm:grid-cols-4">
                  <div>
                    <dt className="text-xs text-zinc-500">Segments</dt>
                    <dd className="mt-0.5 font-mono text-sm text-zinc-200">{stats.total}</dd>
                  </div>
                  <div>
                    <dt className="text-xs text-zinc-500">Failed</dt>
                    <dd
                      className={`mt-0.5 font-mono text-sm ${
                        stats.failed > 0 ? "text-rose-300" : "text-zinc-200"
                      }`}
                    >
                      {stats.failed}
                    </dd>
                  </div>
                  <div>
                    <dt className="text-xs text-zinc-500">Result</dt>
                    <dd
                      className={`mt-0.5 font-mono text-sm ${
                        stats.failed > 0 ? "text-rose-300" : "text-emerald-300"
                      }`}
                    >
                      {stats.failed > 0 ? "Partial" : "Clean"}
                    </dd>
                  </div>
                  <div>
                    <dt className="text-xs text-zinc-500">Integrity</dt>
                    <dd
                      className={`mt-0.5 font-mono text-sm ${
                        stats.integrity === "match"
                          ? "text-emerald-300"
                          : stats.integrity === "mismatch"
                            ? "text-rose-300"
                            : "text-zinc-500"
                      }`}
                    >
                      {stats.integrity === "match"
                        ? "Verified"
                        : stats.integrity === "mismatch"
                          ? "Hash differs"
                          : "No hash"}
                    </dd>
                  </div>
                </dl>

                {(stats.total > 1 || stats.failed > 0) && (
                  <div className="mb-4">
                    <p className="mb-1.5 text-xs text-zinc-500">Per-segment result</p>
                    <div className="flex flex-wrap gap-1">
                      {stats.segmentOk.slice(0, MAX_SEGMENT_CHIPS).map((ok, index) => (
                        <motion.span
                          key={index}
                          initial={{ opacity: 0, scale: 0.5 }}
                          animate={{ opacity: 1, scale: 1 }}
                          transition={{ ...SPRING_POP, delay: index * 0.015 }}
                          title={`Segment ${index + 1}: ${ok ? "recovered" : "failed"}`}
                          className={`inline-flex h-6 min-w-6 items-center justify-center rounded-md border px-1 font-mono text-[10px] ${
                            ok
                              ? "border-emerald-500/25 bg-emerald-500/10 text-emerald-300"
                              : "border-rose-500/30 bg-rose-500/15 text-rose-300"
                          }`}
                        >
                          {index + 1}
                        </motion.span>
                      ))}
                      {stats.total > MAX_SEGMENT_CHIPS && (
                        <span className="inline-flex h-6 items-center rounded-md border border-white/10 bg-white/[0.04] px-1.5 font-mono text-[10px] text-zinc-500">
                          +{stats.total - MAX_SEGMENT_CHIPS} more
                        </span>
                      )}
                    </div>
                  </div>
                )}
              </PopIn>
            )}

            <textarea
              readOnly
              value={output}
              placeholder="The decrypted text will appear here"
              aria-label="Decrypted plaintext"
              className="field-area min-h-[13rem] font-sans text-sm"
            />
          </CardBody>
        </Card>
      </div>
    </FadeIn>
  );
}
