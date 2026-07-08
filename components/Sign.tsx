"use client";

import { useEffect, useMemo, useState } from "react";
import { ArrowRight, Check, Copy, Download, RotateCcw } from "lucide-react";
import { dictToPrivJwk, parsePrivateKeyInput, signMessage } from "@/lib/rsa";
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
} from "@/components/ui/Motion";
import {
  KeyStatusLine,
  SelectedIdentityNotice,
  useParsedKeyInfo,
  WalletKeyPicker,
} from "@/components/ui/KeyInput";
import { useCopy } from "@/components/ui/useCopy";

export default function Sign() {
  const { keys } = useWallet();
  const { addHistory } = useHistory();
  const { sendToVerify } = useWorkbench();
  const toast = useToast();
  const { copied, copy } = useCopy();

  const [privKeyInput, setPrivKeyInput] = useState("");
  const [message, setMessage] = useState("");
  const [signature, setSignature] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [selectedWalletKeyId, setSelectedWalletKeyId] = useState("");

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

  const handleSign = async () => {
    setError(null);
    setLoading(true);
    setSignature("");

    try {
      if (!privKeyInput.trim() || !message.trim()) {
        throw new Error("Load a private key and enter a message first.");
      }

      const privKeyData = await parsePrivateKeyInput(privKeyInput);
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
        description: "Check it in the Verify tab, or hand it out with the message.",
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

    const ok = await copy(signature, "signature");
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
    setMessage("");
    setSignature("");
    setError(null);
  };

  return (
    <FadeIn className="grid gap-4 xl:grid-cols-[minmax(0,1fr)_370px]">
      <div className="space-y-4">
        <Card>
          <CardHeader
            title="Signing key"
            description="The private key never appears in the signature. Verifiers only need the public half."
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
                detail="Signing key loaded from the wallet."
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
                aria-label="Signing private key"
                className="field-area min-h-[11rem]"
              />
            )}
            <KeyStatusLine info={keyInfo} kind="private" />
          </CardBody>
        </Card>

        <Card>
          <CardHeader
            title="Message"
            description="Verification checks this text byte for byte, so even a trailing space counts."
            actions={<FileUpload onFileSelect={setMessage} label="Load text" accept=".txt,.md" />}
          />
          <CardBody>
            <textarea
              value={message}
              onChange={(event) => setMessage(event.target.value)}
              onKeyDown={(event) => {
                if ((event.ctrlKey || event.metaKey) && event.key === "Enter") {
                  event.preventDefault();
                  if (!loading && privKeyInput.trim() && message.trim()) {
                    void handleSign();
                  }
                }
              }}
              placeholder="Type the message to sign"
              aria-label="Message to sign"
              className="field-area min-h-[11rem] font-sans text-sm"
            />
          </CardBody>
        </Card>
      </div>

      <div className="space-y-4">
        <Card>
          <CardHeader
            title="Sign"
            actions={
              <Button variant="ghost" size="sm" onClick={clearAll}>
                <RotateCcw className="h-3.5 w-3.5" />
                Reset
              </Button>
            }
          />
          <CardBody>
            <p className="text-[13px] leading-5 text-zinc-500">
              Signatures use RSA-PSS with SHA-256. The salt is random, so signing the same
              message twice gives two different, equally valid signatures.
            </p>

            {error && (
              <div role="alert" className="notice-danger mt-3">
                {error}
              </div>
            )}

            <Button
              onClick={handleSign}
              disabled={loading || !privKeyInput.trim() || !message.trim()}
              className="mt-4 w-full"
              size="lg"
              title="Ctrl+Enter in the message box also runs this"
            >
              {loading ? "Signing" : "Generate signature"}
            </Button>
          </CardBody>
        </Card>

        <Card>
          <CardHeader
            title="Signature"
            actions={
              signature ? (
                <>
                  <IconButton label="Copy signature" onClick={handleCopy}>
                    {copied === "signature" ? (
                      <Check className="h-4 w-4 animate-pop text-emerald-400" />
                    ) : (
                      <Copy className="h-4 w-4" />
                    )}
                  </IconButton>
                  <IconButton
                    label="Download signature"
                    onClick={() =>
                      downloadTextFile(
                        timestampedFilename("signature", "txt"),
                        signature,
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
            {signature ? (
              <PopIn key={signature}>
                <dl className="mb-4 grid grid-cols-3 gap-3">
                  <div>
                    <dt className="text-xs text-zinc-500">Format</dt>
                    <dd className="mt-0.5 font-mono text-sm text-zinc-200">Hex</dd>
                  </div>
                  <div>
                    <dt className="text-xs text-zinc-500">Length</dt>
                    <dd className="mt-0.5 font-mono text-sm text-zinc-200">{signature.length}</dd>
                  </div>
                  <div>
                    <dt className="text-xs text-zinc-500">Bytes</dt>
                    <dd className="mt-0.5 font-mono text-sm text-zinc-200">
                      {signature.length / 2}
                    </dd>
                  </div>
                </dl>
                <pre className="code-block max-h-72">{signature}</pre>
                <Button
                  variant="secondary"
                  size="sm"
                  onClick={() => sendToVerify({ message, signature })}
                  className="mt-3"
                >
                  Check in Verify
                  <ArrowRight className="h-3.5 w-3.5" />
                </Button>
              </PopIn>
            ) : (
              <EmptyState title="No signature yet">
                Sign a message to get a hex signature you can check in the Verify tab.
              </EmptyState>
            )}
          </CardBody>
        </Card>
      </div>
    </FadeIn>
  );
}
