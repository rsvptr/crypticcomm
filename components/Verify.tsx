"use client";

import { useState } from "react";
import { verifySignature, dictToPubJwk, pemToRSAKeyDict } from "@/lib/rsa";
import { ShieldCheck, Text, Fingerprint, CheckCircle, XCircle, Trash2 } from "lucide-react";
import { useWallet } from "@/components/WalletContext";
import { useHistory } from "@/components/HistoryContext";
import { Card, NeonButton, FadeIn, FileUpload } from "@/components/ui/Motion";

export default function Verify() {
  const { keys } = useWallet();
  const { addHistory } = useHistory();
  const [pubKeyInput, setPubKeyInput] = useState("");
  const [message, setMessage] = useState("");
  const [signature, setSignature] = useState("");
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<boolean | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [selectedWalletKeyId, setSelectedWalletKeyId] = useState("");

  const handleVerify = async () => {
    setError(null);
    setLoading(true);
    setResult(null);
    
    try {
      if (!pubKeyInput.trim() || !message.trim() || !signature.trim()) {
        throw new Error("All fields are required.");
      }

      let pubKeyData;
      const trimmedInput = pubKeyInput.trim();
      if (trimmedInput.startsWith("-----BEGIN PUBLIC KEY-----")) {
        try {
          pubKeyData = await pemToRSAKeyDict(trimmedInput, "public");
        } catch (e) {
          throw new Error("Invalid Public Key PEM format.");
        }
      } else {
        try {
          pubKeyData = JSON.parse(trimmedInput);
        } catch (e) {
          throw new Error("Invalid Public Key JSON format.");
        }
      }

      const pubJwk = dictToPubJwk(pubKeyData.n, pubKeyData.e);
      
      const isValid = await verifySignature(message, signature.trim(), pubJwk);
      setResult(isValid);
      
      const keyName = selectedWalletKeyId ? keys.find(k => k.id === selectedWalletKeyId)?.name : undefined;
      addHistory({
        type: "Verify",
        details: {
          message: message,
          output: "Signature was: " + (isValid ? "Valid" : "Invalid"),
          keyName: keyName,
          status: isValid ? "Success" : "Failed"
        }
      });

    } catch (e: any) {
      setError(e.message);
      addHistory({
        type: "Verify",
        details: { status: "Error", message: e.message }
      });
    } finally {
      setLoading(false);
    }
  };

  const loadFromWallet = (e: React.ChangeEvent<HTMLSelectElement>) => {
    const k = keys.find(k => k.id === e.target.value);
    if (k) {
      setSelectedWalletKeyId(k.id);
      setPubKeyInput(JSON.stringify(k.keys.public, null, 2));
    } else {
      setSelectedWalletKeyId("");
      setPubKeyInput("");
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
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <FadeIn className="space-y-6">
          <Card>
            <div className="flex justify-between items-center mb-4">
                <h2 className="text-xl font-semibold text-slate-100 flex items-center gap-2">
                    <ShieldCheck className="w-5 h-5 text-indigo-400" /> 1. Signer&apos;s Public Key
                </h2>
                <FileUpload onFileSelect={(data) => { setPubKeyInput(data); setSelectedWalletKeyId(""); }} label="Load Key" accept=".json,.pem,.txt" />
            </div>
             {keys.length > 0 && (
               <div className="mb-4">
                 <select 
                   onChange={loadFromWallet}
                   value={selectedWalletKeyId}
                   className="w-full bg-slate-800 border border-slate-700 rounded-lg p-2 text-sm text-slate-300 focus:ring-2 focus:ring-indigo-500"
                 >
                   <option value="">-- Load from Wallet --</option>
                   {keys.map(k => (
                     <option key={k.id} value={k.id}>{k.name}</option>
                   ))}
                 </select>
               </div>
            )}
            
            {selectedWalletKeyId ? (
              <div className="w-full h-24 bg-slate-900 border border-emerald-500/30 rounded-lg p-4 flex flex-col justify-center items-center text-center">
                <span className="text-emerald-400 font-medium mb-2">Wallet Key Selected</span>
                <span className="text-slate-300 text-sm">{keys.find(k => k.id === selectedWalletKeyId)?.name}</span>
                <button onClick={() => setSelectedWalletKeyId("")} className="mt-3 text-xs text-indigo-400 hover:underline">Show Raw / Edit</button>
              </div>
            ) : (
              <textarea
                value={pubKeyInput}
                onChange={(e) => { setPubKeyInput(e.target.value); setSelectedWalletKeyId(""); }}
                placeholder='Paste Public Key JSON or PEM...'
                className="w-full h-24 bg-slate-950 border border-slate-700 rounded-lg p-3 text-xs font-mono text-slate-300 focus:ring-2 focus:ring-indigo-500 focus:outline-none transition-colors resize-none"
              />
            )}
          </Card>

          <Card>
            <div className="flex justify-between items-center mb-4">
                <h2 className="text-xl font-semibold text-slate-100 flex items-center gap-2">
                    <Text className="w-5 h-5 text-indigo-400" /> 2. Original Message
                </h2>
                 <FileUpload onFileSelect={setMessage} label="Load Text" accept=".txt,.md" />
            </div>
            <textarea
              value={message}
              onChange={(e) => setMessage(e.target.value)}
              placeholder="The plain text message..."
              className="w-full h-24 bg-slate-950 border border-slate-700 rounded-lg p-3 text-sm text-slate-300 focus:ring-2 focus:ring-indigo-500 focus:outline-none transition-colors resize-none"
            />
          </Card>

          <Card>
            <div className="flex justify-between items-center mb-4">
                <h2 className="text-xl font-semibold text-slate-100 flex items-center gap-2">
                    <Fingerprint className="w-5 h-5 text-indigo-400" /> 3. Signature
                </h2>
                <FileUpload onFileSelect={setSignature} label="Load Text" accept=".txt" />
            </div>
            <textarea
              value={signature}
              onChange={(e) => setSignature(e.target.value)}
              placeholder="Paste the hex signature string..."
              className="w-full h-24 bg-slate-950 border border-slate-700 rounded-lg p-3 text-xs font-mono text-slate-300 focus:ring-2 focus:ring-indigo-500 focus:outline-none transition-colors resize-none"
            />
          </Card>
        </FadeIn>

        <FadeIn delay={0.1} className="flex flex-col gap-6">
          <Card>
             <div className="flex justify-end mb-2">
                 <button onClick={clearAll} className="text-xs text-slate-500 hover:text-red-400 flex items-center gap-1">
                    <Trash2 className="w-3 h-3" /> Clear All
                </button>
             </div>
             <NeonButton 
              onClick={handleVerify} 
              disabled={loading || !pubKeyInput || !message || !signature}
              className="w-full py-4 text-lg"
            >
              {loading ? "Verifying..." : "Verify Signature"}
            </NeonButton>
          </Card>

          {result !== null && (
            <div className="flex-1 flex items-center justify-center">
              <Card className={result ? "bg-emerald-500/10 border-emerald-500/50 w-full" : "bg-red-500/10 border-red-500/50 w-full"}>
                <div className="flex flex-col items-center justify-center py-8 text-center">
                    {result ? (
                        <>
                            <div className="w-20 h-20 rounded-full bg-emerald-500 flex items-center justify-center shadow-[0_0_30px_rgba(16,185,129,0.5)] mb-4">
                                <CheckCircle className="w-10 h-10 text-white" />
                            </div>
                            <h3 className="text-2xl font-bold text-white mb-2">Verified Valid</h3>
                            <p className="text-emerald-200">The signature matches the message and public key.</p>
                        </>
                    ) : (
                        <>
                            <div className="w-20 h-20 rounded-full bg-red-500 flex items-center justify-center shadow-[0_0_30px_rgba(239,68,68,0.5)] mb-4">
                                <XCircle className="w-10 h-10 text-white" />
                            </div>
                            <h3 className="text-2xl font-bold text-white mb-2">Verification Failed</h3>
                            <p className="text-red-200">The signature is invalid or the message has been tampered with.</p>
                        </>
                    )}
                </div>
              </Card>
            </div>
          )}

           {error && (
              <div className="p-3 bg-red-500/10 border border-red-500/20 rounded-lg text-xs text-red-200 flex items-center gap-2">
                <XCircle className="w-4 h-4" /> {error}
              </div>
            )}
        </FadeIn>
      </div>
    </div>
  );
}
