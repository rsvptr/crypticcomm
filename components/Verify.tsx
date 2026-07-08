"use client";

import { useEffect, useMemo, useState } from "react";
import { motion } from "framer-motion";
import { CheckCircle2, RotateCcw, XCircle } from "lucide-react";
import { dictToPubJwk, parsePublicKeyInput, verifySignature } from "@/lib/rsa";
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
  SPRING_POP,
  SPRING_SOFT,
} from "@/components/ui/Motion";
import {
  KeyStatusLine,
  SelectedIdentityNotice,
  useParsedKeyInfo,
  WalletKeyPicker,
} from "@/components/ui/KeyInput";

export default function Verify() {
  const { keys } = useWallet();
  const { addHistory } = useHistory();
  const { consumeVerifyHandoff } = useWorkbench();
  const toast = useToast();

  const [pubKeyInput, setPubKeyInput] = useState("");
  const [message, setMessage] = useState("");
  const [signature, setSignature] = useState("");
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<boolean | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [selectedWalletKeyId, setSelectedWalletKeyId] = useState("");

  // Pick up a message and signature handed over from the Sign tab. The key is
  // left for the user to choose; needing the right public key is the lesson.
  useEffect(() => {
    const handoff = consumeVerifyHandoff();
    if (handoff) {
      setMessage(handoff.message);
      setSignature(handoff.signature);
    }
  }, [consumeVerifyHandoff]);

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

  const handleVerify = async () => {
    setError(null);
    setLoading(true);
    setResult(null);

    try {
      if (!pubKeyInput.trim() || !message.trim() || !signature.trim()) {
        throw new Error("A public key, the message, and the signature are all required.");
      }

      const pubKeyData = await parsePublicKeyInput(pubKeyInput);
      const pubJwk = dictToPubJwk(pubKeyData.n, pubKeyData.e);
      const isValid = await verifySignature(message, signature.trim(), pubJwk);

      setResult(isValid);
      addHistory({
        type: "Verify",
        details: {
          message,
          output: isValid ? "Signature was valid." : "Signature was invalid.",
          keyName: selectedWalletKey?.name,
          status: isValid ? "Success" : "Invalid",
        },
      });
      if (isValid) {
        toast.success({ title: "Signature verified" });
      } else {
        toast.error({ title: "Signature doesn't match" });
      }
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
    <FadeIn className="grid gap-4 xl:grid-cols-[minmax(0,1fr)_370px]">
      <div className="space-y-4">
        <Card>
          <CardHeader
            title="Signer's public key"
            description="Verification proves the message was signed by whoever holds the matching private key."
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
                aria-label="Signer's public key"
                className="field-area min-h-[10rem]"
              />
            )}
            <KeyStatusLine info={keyInfo} kind="public" />
          </CardBody>
        </Card>

        <Card>
          <CardHeader
            title="Original message"
            description="Has to match what was signed exactly. One changed character fails the check."
            actions={<FileUpload onFileSelect={setMessage} label="Load text" accept=".txt,.md" />}
          />
          <CardBody>
            <textarea
              value={message}
              onChange={(event) => setMessage(event.target.value)}
              placeholder="Paste the original message"
              aria-label="Original message"
              className="field-area min-h-[10rem] font-sans text-sm"
            />
          </CardBody>
        </Card>

        <Card>
          <CardHeader
            title="Signature"
            description="The hex string produced by the Sign tab."
            actions={<FileUpload onFileSelect={setSignature} label="Load text" accept=".txt" />}
          />
          <CardBody>
            <textarea
              value={signature}
              onChange={(event) => setSignature(event.target.value)}
              onKeyDown={(event) => {
                if ((event.ctrlKey || event.metaKey) && event.key === "Enter") {
                  event.preventDefault();
                  if (!loading && pubKeyInput.trim() && message.trim() && signature.trim()) {
                    void handleVerify();
                  }
                }
              }}
              placeholder="Paste the hex signature"
              aria-label="Signature"
              className="field-area min-h-[8rem]"
            />
          </CardBody>
        </Card>
      </div>

      <div className="space-y-4">
        <Card>
          <CardHeader
            title="Verify"
            actions={
              <Button variant="ghost" size="sm" onClick={clearAll}>
                <RotateCcw className="h-3.5 w-3.5" />
                Reset
              </Button>
            }
          />
          <CardBody>
            <p className="text-[13px] leading-5 text-zinc-500">
              One check ties all three inputs together: the message, the signature, and the
              key. If any of them changed since signing, verification fails.
            </p>

            {error && (
              <div role="alert" className="notice-danger mt-3">
                {error}
              </div>
            )}

            <Button
              onClick={handleVerify}
              disabled={loading || !pubKeyInput.trim() || !message.trim() || !signature.trim()}
              className="mt-4 w-full"
              size="lg"
              title="Ctrl+Enter in the signature box also runs this"
            >
              {loading ? "Verifying" : "Verify signature"}
            </Button>
          </CardBody>
        </Card>

        <Card>
          <CardHeader title="Result" />
          <CardBody>
            {result === null ? (
              <EmptyState title="No check run yet">
                Fill in the three fields and run the verification to see the outcome here.
              </EmptyState>
            ) : (
              <motion.div
                key={String(result)}
                initial={{ opacity: 0, y: 10, scale: 0.97 }}
                animate={{ opacity: 1, y: 0, scale: 1 }}
                transition={SPRING_SOFT}
                className={`rounded-lg border px-5 py-6 text-center ${
                  result
                    ? "border-emerald-500/25 bg-emerald-500/[0.07]"
                    : "border-rose-500/25 bg-rose-500/[0.07]"
                }`}
              >
                <motion.span
                  initial={{ scale: 0.3, rotate: result ? -20 : 0 }}
                  animate={{ scale: 1, rotate: 0 }}
                  transition={{ ...SPRING_POP, delay: 0.08 }}
                  className="inline-flex"
                >
                  {result ? (
                    <CheckCircle2 className="h-8 w-8 text-emerald-400" />
                  ) : (
                    <XCircle className="h-8 w-8 text-rose-400" />
                  )}
                </motion.span>
                {result ? (
                  <>
                    <h3 className="mt-3 text-base font-semibold text-emerald-200">
                      Signature is valid
                    </h3>
                    <p className="mt-1.5 text-[13px] leading-5 text-zinc-400">
                      The message is untouched and was signed by this key&apos;s owner.
                    </p>
                  </>
                ) : (
                  <>
                    <h3 className="mt-3 text-base font-semibold text-rose-200">
                      Signature is invalid
                    </h3>
                    <p className="mt-1.5 text-[13px] leading-5 text-zinc-400">
                      The message was altered, the signature is corrupted, or this isn&apos;t
                      the signer&apos;s key.
                    </p>
                  </>
                )}
              </motion.div>
            )}
          </CardBody>
        </Card>
      </div>
    </FadeIn>
  );
}
