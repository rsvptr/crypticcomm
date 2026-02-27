"use client";

import { useState } from "react";
import { 
  decryptSegmentOAEP, 
  decryptSegmentTextbook, 
  dictToPrivJwk, 
  sha256,
  pemToRSAKeyDict
} from "@/lib/rsa";
import { Unlock, FileJson, CheckCircle, XCircle, Trash2, Download, Copy, Check } from "lucide-react";
import { useWallet } from "@/components/WalletContext";
import { useHistory } from "@/components/HistoryContext";
import { Card, NeonButton, FadeIn, FileUpload } from "@/components/ui/Motion";

export default function Decrypt() {
  const { keys } = useWallet();
  const { addHistory } = useHistory();
  const [privKeyInput, setPrivKeyInput] = useState("");
  const [encryptedInput, setEncryptedInput] = useState("");
  const [loading, setLoading] = useState(false);
  const [output, setOutput] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [stats, setStats] = useState<any>(null);
  const [copied, setCopied] = useState(false);
  const [selectedWalletKeyId, setSelectedWalletKeyId] = useState("");

  const handleDecrypt = async () => {
    setError(null);
    setLoading(true);
    setOutput("");
    setStats(null);
    setCopied(false);
    
    try {
      if (!privKeyInput.trim() || !encryptedInput.trim()) {
        throw new Error("Private Key and Encrypted Message are required.");
      }

      // Parse Inputs
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
      
      let encData;
      try {
        encData = JSON.parse(encryptedInput);
      } catch (e) {
        throw new Error("Invalid Encrypted Message JSON.");
      }

      if (!encData.segments || !Array.isArray(encData.segments)) {
        throw new Error("Invalid encrypted message format (missing segments).");
      }

      const useOAEP = encData.oaep;
      const decryptedSegments: string[] = [];
      let failCount = 0;

      // Prepare JWK if OAEP
      let privJwk;
      if (useOAEP) {
          try {
            privJwk = dictToPrivJwk(privKeyData);
          } catch (e: any) {
             throw new Error("OAEP decryption requires a full private key (p, q). " + e.message);
          }
      }

      for (const seg of encData.segments) {
        let pt;
        if (useOAEP && privJwk) {
            pt = await decryptSegmentOAEP(seg, privJwk);
        } else {
            pt = decryptSegmentTextbook(seg, privKeyData.n, privKeyData.d);
        }

        if (pt.startsWith("[Decryption error")) {
            failCount++;
        }
        decryptedSegments.push(pt);
      }

      const finalMsg = decryptedSegments.join("");
      setOutput(finalMsg);
      setStats({
          total: encData.segments.length,
          failed: failCount,
          sha256: await sha256(finalMsg)
      });
      
      const keyName = selectedWalletKeyId ? keys.find(k => k.id === selectedWalletKeyId)?.name : undefined;
      addHistory({
        type: "Decrypt",
        details: {
          message: "Encrypted JSON (" + encData.segments.length + " segments)",
          output: finalMsg,
          keyName: keyName,
          status: failCount > 0 ? "Partial Failure" : "Success"
        }
      });

    } catch (e: any) {
      setError(e.message);
      addHistory({
        type: "Decrypt",
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

  const handleCopy = () => {
      if(output) {
          navigator.clipboard.writeText(output);
          setCopied(true);
          setTimeout(() => setCopied(false), 2000);
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
    <div className="space-y-6">
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <FadeIn className="space-y-6">
          <Card>
            <div className="flex justify-between items-center mb-4">
                <h2 className="text-xl font-semibold text-slate-100 flex items-center gap-2">
                    <Unlock className="w-5 h-5 text-indigo-400" /> 1. Private Key
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

            <div className="mb-4">
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
                  placeholder='Paste Private Key JSON or PEM...'
                  className="w-full h-32 bg-slate-950 border border-slate-700 rounded-lg p-3 text-xs font-mono text-red-200/80 focus:ring-2 focus:ring-indigo-500 focus:outline-none transition-colors resize-none"
                />
              )}
            </div>
          </Card>

          <Card>
            <div className="flex justify-between items-center mb-4">
                <h2 className="text-xl font-semibold text-slate-100 flex items-center gap-2">
                    <FileJson className="w-5 h-5 text-indigo-400" /> 2. Encrypted Message
                </h2>
                <FileUpload onFileSelect={setEncryptedInput} label="Load JSON" />
            </div>
            <div className="mb-4">
              <textarea
                value={encryptedInput}
                onChange={(e) => setEncryptedInput(e.target.value)}
                placeholder='Paste Encrypted JSON...'
                className="w-full h-32 bg-slate-950 border border-slate-700 rounded-lg p-3 text-xs font-mono text-slate-300 focus:ring-2 focus:ring-indigo-500 focus:outline-none transition-colors resize-none"
              />
            </div>
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
                    onClick={handleDecrypt}
                    disabled={loading || !privKeyInput || !encryptedInput}
                    className="w-full"
                >
                    {loading ? "Decrypting..." : "Decrypt Message"}
                </NeonButton>

                {error && (
                    <div className="mt-4 p-3 bg-red-500/10 border border-red-500/20 rounded-lg text-xs text-red-200">
                        {error}
                    </div>
                )}
            </Card>

            <Card className="flex-1 flex flex-col border-indigo-500/30">
                <div className="flex justify-between items-center mb-2">
                    <h2 className="text-lg font-semibold text-indigo-400 flex items-center gap-2">
                        <span>Decrypted Output</span>
                        {stats && (
                            <span className={`text-xs px-2 py-1 rounded-full border ${stats.failed > 0 ? 'bg-red-500/10 border-red-500/20 text-red-300' : 'bg-emerald-500/10 border-emerald-500/20 text-emerald-300'}`}>
                                {stats.failed > 0 ? `${stats.failed} Errors` : 'Success'}
                            </span>
                        )}
                    </h2>
                     <button 
                            onClick={handleCopy} 
                            className="p-1.5 hover:bg-slate-800 rounded text-slate-400 hover:text-white transition-colors"
                            title="Copy Text"
                        >
                            {copied ? <Check className="w-4 h-4 text-emerald-400" /> : <Copy className="w-4 h-4" />}
                    </button>
                </div>
                <textarea
                    readOnly
                    value={output}
                    placeholder="Decrypted text will appear here..."
                    className="flex-1 w-full bg-slate-950 border border-slate-900 rounded-lg p-4 text-sm text-indigo-100 font-mono focus:outline-none resize-none min-h-[200px]"
                />
            </Card>
        </FadeIn>
      </div>
    </div>
  );
}
