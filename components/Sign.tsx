"use client";

import { useState } from "react";
import { signMessage, dictToPrivJwk, pemToRSAKeyDict } from "@/lib/rsa";
import { PenTool, FileSignature, AlertCircle, Check, Copy, Trash2 } from "lucide-react";
import { useWallet } from "@/components/WalletContext";
import { useHistory } from "@/components/HistoryContext";
import { Card, NeonButton, FadeIn, FileUpload } from "@/components/ui/Motion";
import clsx from "clsx";

export default function Sign() {
  const { keys } = useWallet();
  const { addHistory } = useHistory();
  const [privKeyInput, setPrivKeyInput] = useState("");
  const [message, setMessage] = useState("");
  const [signature, setSignature] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);
  const [selectedWalletKeyId, setSelectedWalletKeyId] = useState("");

  const handleSign = async () => {
    setError(null);
    setLoading(true);
    setSignature("");
    setCopied(false);
    
    try {
      if (!privKeyInput.trim() || !message.trim()) {
        throw new Error("Private Key and Message are required.");
      }

      let privKeyData;
      const trimmedInput = privKeyInput.trim();
      if (trimmedInput.startsWith("-----BEGIN PRIVATE KEY-----")) {
        try {
          privKeyData = await pemToRSAKeyDict(trimmedInput, "private");
        } catch (e) {
          throw new Error("Invalid Private Key PEM format.");
        }
      } else {
        try {
          privKeyData = JSON.parse(trimmedInput);
        } catch (e) {
          throw new Error("Invalid Private Key JSON format.");
        }
      }

      // Convert to JWK
      const privJwk = dictToPrivJwk(privKeyData);
      
      // Sign
      const sig = await signMessage(message, privJwk);
      setSignature(sig);
      
      const keyName = selectedWalletKeyId ? keys.find(k => k.id === selectedWalletKeyId)?.name : undefined;
      addHistory({
        type: "Sign",
        details: {
          message: message,
          output: sig,
          keyName: keyName,
          status: "Success"
        }
      });

    } catch (e: any) {
      setError(e.message);
      addHistory({
        type: "Sign",
        details: { status: "Failed", message: e.message }
      });
    } finally {
      setLoading(false);
    }
  };

  const loadFromWallet = (e: React.ChangeEvent<HTMLSelectElement>) => {
    const k = keys.find(k => k.id === e.target.value);
    if (k) {
      setSelectedWalletKeyId(k.id);
      setPrivKeyInput(JSON.stringify(k.keys.private, null, 2));
    } else {
      setSelectedWalletKeyId("");
      setPrivKeyInput("");
    }
  };

  const clearAll = () => {
      setSelectedWalletKeyId("");
      setPrivKeyInput("");
      setMessage("");
      setSignature("");
      setError(null);
  };

  const handleCopy = () => {
      if(signature) {
          navigator.clipboard.writeText(signature);
          setCopied(true);
          setTimeout(() => setCopied(false), 2000);
      }
  };

  return (
    <div className="space-y-6">
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <FadeIn className="space-y-6">
          <Card>
            <div className="flex justify-between items-center mb-4">
                <h2 className="text-xl font-semibold text-slate-100 flex items-center gap-2">
                    <PenTool className="w-5 h-5 text-indigo-400" /> 1. Private Key
                </h2>
                <FileUpload onFileSelect={(data) => { setPrivKeyInput(data); setSelectedWalletKeyId(""); }} label="Load Key" accept=".json,.pem,.txt" />
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
              <div className="w-full h-32 bg-slate-900 border border-red-500/30 rounded-lg p-4 flex flex-col justify-center items-center text-center">
                <span className="text-red-400 font-medium mb-2">Wallet Key Selected</span>
                <span className="text-slate-300 text-sm">{keys.find(k => k.id === selectedWalletKeyId)?.name}</span>
                <button onClick={() => setSelectedWalletKeyId("")} className="mt-3 text-xs text-indigo-400 hover:underline">Show Raw / Edit</button>
              </div>
            ) : (
              <textarea
                value={privKeyInput}
                onChange={(e) => { setPrivKeyInput(e.target.value); setSelectedWalletKeyId(""); }}
                placeholder='Paste Private Key JSON or PEM here...'
                className="w-full h-32 bg-slate-950 border border-slate-700 rounded-lg p-3 text-xs font-mono text-red-200/80 focus:ring-2 focus:ring-indigo-500 focus:outline-none transition-colors resize-none"
              />
            )}
          </Card>

          <Card>
            <div className="flex justify-between items-center mb-4">
                <h2 className="text-xl font-semibold text-slate-100 flex items-center gap-2">
                    <FileSignature className="w-5 h-5 text-indigo-400" /> 2. Message to Sign
                </h2>
                <FileUpload onFileSelect={setMessage} label="Load Text" accept=".txt,.md" />
            </div>
            <textarea
              value={message}
              onChange={(e) => setMessage(e.target.value)}
              placeholder="Enter the message you want to prove you wrote..."
              className="w-full h-32 bg-slate-950 border border-slate-700 rounded-lg p-3 text-sm text-slate-300 focus:ring-2 focus:ring-indigo-500 focus:outline-none transition-colors resize-none"
            />
          </Card>
        </FadeIn>

        <FadeIn delay={0.1} className="flex flex-col gap-6">
          <Card>
             <div className="flex justify-between items-center mb-4">
                <h2 className="text-xl font-semibold text-slate-100">Action</h2>
                <button onClick={clearAll} className="text-xs text-slate-500 hover:text-red-400 flex items-center gap-1">
                    <Trash2 className="w-3 h-3" /> Clear All
                </button>
            </div>
            <NeonButton 
              onClick={handleSign} 
              disabled={loading || !privKeyInput || !message}
              className="w-full"
            >
              {loading ? "Signing..." : "Generate Signature"}
            </NeonButton>

            {error && (
              <div className="mt-4 p-3 bg-red-500/10 border border-red-500/20 rounded-lg text-xs text-red-200 flex items-center gap-2">
                <AlertCircle className="w-4 h-4" /> {error}
              </div>
            )}
          </Card>

          {signature && (
            <Card className="flex-1 flex flex-col">
              <h2 className="text-lg font-semibold mb-2 text-emerald-400">Digital Signature</h2>
              <div className="bg-slate-950 p-4 rounded-lg border border-slate-900 flex-1 relative group">
                <p className="font-mono text-xs text-emerald-100/80 break-all">{signature}</p>
                <button
                  onClick={handleCopy}
                  className="absolute top-2 right-2 p-2 bg-slate-800 rounded opacity-0 group-hover:opacity-100 transition-opacity"
                >
                  {copied ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3 text-white" />}
                </button>
              </div>
              <p className="text-xs text-slate-500 mt-2">
                Share this signature along with the original message. Anyone with your public key can verify it.
              </p>
            </Card>
          )}
        </FadeIn>
      </div>
    </div>
  );
}
