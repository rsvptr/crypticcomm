"use client";

import { useEffect, useMemo, useState } from "react";
import { ArrowRight, Check, Copy, Download, RotateCcw } from "lucide-react";
import {
  dictToPubJwk,
  encryptSegmentOAEP,
  encryptSegmentTextbook,
  parsePublicKeyInput,
  segmentMessage,
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
  EmptyState,
  FadeIn,
  FileUpload,
  IconButton,
  PopIn,
  SegmentedControl,
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
  num_segments: number;
  key_bits: number;
  message_sha256: string;
  timestamp: string;
}

export default function Encrypt() {
  const { keys } = useWallet();
  const { addHistory } = useHistory();
  const { sendToDecrypt } = useWorkbench();
  const toast = useToast();
  const { copied, copy } = useCopy();

  const [pubKeyInput, setPubKeyInput] = useState("");
  const [message, setMessage] = useState("");
  const [useOAEP, setUseOAEP] = useState(true);
  const [loading, setLoading] = useState(false);
  const [output, setOutput] = useState<EncryptedPayload | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [selectedWalletKeyId, setSelectedWalletKeyId] = useState("");

  const selectedWalletKey = useMemo(
    () => keys.find((key) => key.id === selectedWalletKeyId),
    [keys, selectedWalletKeyId]
  );
  const keyInfo = useParsedKeyInfo(pubKeyInput, "public");

  // If the selected wallet identity disappears (wallet locked, key deleted),
  // scrub the key material that came from it.
  useEffect(() => {
    if (selectedWalletKeyId && !selectedWalletKey) {
      setSelectedWalletKeyId("");
      setPubKeyInput("");
    }
  }, [selectedWalletKey, selectedWalletKeyId]);

  const sizeEstimate = useMemo(() => {
    if (!message) {
      return null;
    }

    const bytes = new TextEncoder().encode(message).length;
    if (keyInfo.state !== "valid") {
      return { bytes, segments: null as number | null };
    }

    const keyBytes = Math.ceil(keyInfo.bits / 8);
    const maxSegmentBytes = useOAEP ? keyBytes - 66 : keyBytes - 1;
    if (maxSegmentBytes <= 0) {
      return { bytes, segments: null as number | null };
    }

    return { bytes, segments: Math.ceil(bytes / maxSegmentBytes) };
  }, [message, keyInfo, useOAEP]);

  const outputJson = output ? JSON.stringify(output, null, 2) : "";

  const handleEncrypt = async () => {
    setError(null);
    setLoading(true);
    setOutput(null);

    try {
      if (!pubKeyInput.trim() || !message.trim()) {
        throw new Error("Load a public key and enter a message first.");
      }

      const pubKeyData = await parsePublicKeyInput(pubKeyInput);
      const modulus = BigInt(pubKeyData.n);
      const keyBits = modulus.toString(2).length;
      const keyBytes = Math.ceil(keyBits / 8);
      const maxSegmentBytes = useOAEP ? keyBytes - 66 : keyBytes - 1;

      if (maxSegmentBytes <= 0) {
        throw new Error("This key is too small for the selected mode.");
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
          output: `Encrypted payload with ${segments.length} segment${segments.length === 1 ? "" : "s"}`,
          keyName: selectedWalletKey?.name,
          status: "Success",
        },
      });
      toast.success({
        title: "Message encrypted",
        description: `${segments.length} segment${segments.length === 1 ? "" : "s"}, ${
          useOAEP ? "OAEP" : "textbook RSA"
        }.`,
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

    const ok = await copy(outputJson, "payload");
    if (ok) {
      toast.success({
        title: "Payload copied",
        description: "Paste it into the Decrypt tab to complete the round trip.",
      });
    } else {
      toast.error({
        title: "Copy failed",
        description: "The browser blocked clipboard access.",
      });
    }
  };

  const clearAll = () => {
    setSelectedWalletKeyId("");
    setPubKeyInput("");
    setMessage("");
    setOutput(null);
    setError(null);
    setUseOAEP(true);
  };

  return (
    <FadeIn className="grid gap-4 xl:grid-cols-[minmax(0,1fr)_370px]">
      <div className="space-y-4">
        <Card>
          <CardHeader
            title="Recipient public key"
            description="The message gets encrypted for whoever holds the matching private key."
            actions={
              <FileUpload
                onFileSelect={(data) => {
                  setPubKeyInput(data);
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
                  setPubKeyInput(JSON.stringify(key.keys.public, null, 2));
                } else {
                  setSelectedWalletKeyId("");
                  setPubKeyInput("");
                }
              }}
            />
            {selectedWalletKey ? (
              <SelectedIdentityNotice
                name={selectedWalletKey.name}
                detail="Public key loaded from the wallet."
                onClear={() => setSelectedWalletKeyId("")}
              />
            ) : (
              <textarea
                value={pubKeyInput}
                onChange={(event) => {
                  setPubKeyInput(event.target.value);
                  setSelectedWalletKeyId("");
                }}
                placeholder="Paste a public key as JSON or PEM"
                aria-label="Recipient public key"
                className="field-area min-h-[11rem]"
              />
            )}
            <KeyStatusLine info={keyInfo} kind="public" />
          </CardBody>
        </Card>

        <Card>
          <CardHeader
            title="Message"
            description="Long messages are split into segments that each fit the key size."
            actions={<FileUpload onFileSelect={setMessage} label="Load text" accept=".txt,.json,.md" />}
          />
          <CardBody>
            <textarea
              value={message}
              onChange={(event) => setMessage(event.target.value)}
              onKeyDown={(event) => {
                if ((event.ctrlKey || event.metaKey) && event.key === "Enter") {
                  event.preventDefault();
                  if (!loading && pubKeyInput.trim() && message.trim()) {
                    void handleEncrypt();
                  }
                }
              }}
              placeholder="Type the message to encrypt"
              aria-label="Message to encrypt"
              className="field-area min-h-[11rem] font-sans text-sm"
            />
            {sizeEstimate && (
              <p className="mt-2 font-mono text-xs text-zinc-600 [font-variant-numeric:tabular-nums]">
                {sizeEstimate.bytes} byte{sizeEstimate.bytes === 1 ? "" : "s"}
                {sizeEstimate.segments !== null &&
                  ` · about ${sizeEstimate.segments} ${useOAEP ? "OAEP" : "textbook"} segment${
                    sizeEstimate.segments === 1 ? "" : "s"
                  } with this key`}
              </p>
            )}
          </CardBody>
        </Card>
      </div>

      <div className="space-y-4">
        <Card>
          <CardHeader
            title="Mode"
            actions={
              <Button variant="ghost" size="sm" onClick={clearAll}>
                <RotateCcw className="h-3.5 w-3.5" />
                Reset
              </Button>
            }
          />
          <CardBody>
            <SegmentedControl
              label="Encryption mode"
              options={[
                { value: "oaep", label: "OAEP", hint: "randomized padding" },
                { value: "textbook", label: "Textbook", hint: "no padding" },
              ]}
              value={useOAEP ? "oaep" : "textbook"}
              onChange={(value) => setUseOAEP(value === "oaep")}
            />

            {useOAEP ? (
              <p className="mt-3 text-[13px] leading-5 text-zinc-500">
                OAEP adds random padding, so encrypting the same message twice gives different
                ciphertexts. This is the mode to use.
              </p>
            ) : (
              <div className="notice-warning mt-3">
                Textbook RSA is deliberately insecure. The same plaintext always produces the
                same ciphertext, which is exactly the weakness this mode is here to demonstrate.
              </div>
            )}

            {error && (
              <div role="alert" className="notice-danger mt-3">
                {error}
              </div>
            )}

            <Button
              onClick={handleEncrypt}
              disabled={loading || !pubKeyInput.trim() || !message.trim()}
              className="mt-4 w-full"
              size="lg"
              title="Ctrl+Enter in the message box also runs this"
            >
              {loading ? "Encrypting" : "Encrypt message"}
            </Button>
          </CardBody>
        </Card>

        <Card>
          <CardHeader
            title="Encrypted payload"
            actions={
              output ? (
                <>
                  <IconButton label="Copy payload JSON" onClick={handleCopy}>
                    {copied === "payload" ? (
                      <Check className="h-4 w-4 animate-pop text-emerald-400" />
                    ) : (
                      <Copy className="h-4 w-4" />
                    )}
                  </IconButton>
                  <IconButton
                    label="Download payload JSON"
                    onClick={() =>
                      downloadTextFile(
                        timestampedFilename("encrypted-message", "json"),
                        outputJson,
                        "application/json"
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
            {output ? (
              <PopIn key={output.timestamp}>
                <dl className="mb-4 grid grid-cols-3 gap-3">
                  <div>
                    <dt className="text-xs text-zinc-500">Segments</dt>
                    <dd className="mt-0.5 font-mono text-sm text-zinc-200">
                      {output.num_segments}
                    </dd>
                  </div>
                  <div>
                    <dt className="text-xs text-zinc-500">Mode</dt>
                    <dd className="mt-0.5 font-mono text-sm text-zinc-200">
                      {output.oaep ? "OAEP" : "Textbook"}
                    </dd>
                  </div>
                  <div>
                    <dt className="text-xs text-zinc-500">Key size</dt>
                    <dd className="mt-0.5 font-mono text-sm text-zinc-200">
                      {output.key_bits} bits
                    </dd>
                  </div>
                </dl>
                <pre className="code-block max-h-72">{outputJson}</pre>
                <Button
                  variant="secondary"
                  size="sm"
                  onClick={() => sendToDecrypt(outputJson)}
                  className="mt-3"
                >
                  Open in Decrypt
                  <ArrowRight className="h-3.5 w-3.5" />
                </Button>
              </PopIn>
            ) : (
              <EmptyState title="Nothing encrypted yet">
                The segmented payload, message hash, and mode metadata will appear here.
              </EmptyState>
            )}
          </CardBody>
        </Card>
      </div>
    </FadeIn>
  );
}
