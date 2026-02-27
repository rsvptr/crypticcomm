"use client";

import { useState } from "react";
import { 
  segmentMessage, 
  encryptSegmentOAEP, 
  encryptSegmentTextbook, 
  dictToPubJwk, 
  sha256,
  pemToRSAKeyDict
} from "@/lib/rsa";
import { Lock, FileJson, Info, AlertTriangle, Download, Trash2, Copy, Check } from "lucide-react";
import { useWallet } from "@/components/WalletContext";
import { useHistory } from "@/components/HistoryContext";
import { Card, NeonButton, FadeIn, FileUpload } from "@/components/ui/Motion";

export default function Encrypt() {
  const { keys } = useWallet();
  const { addHistory } = useHistory();
  const [pubKeyInput, setPubKeyInput] = useState("");
  const [message, setMessage] = useState("");
  const [useOAEP, setUseOAEP] = useState(true);
  const [loading, setLoading] = useState(false);
  const [output, setOutput] = useState<any>(null);
  const [error, setError] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);
  const [selectedWalletKeyId, setSelectedWalletKeyId] = useState("");

  const handleEncrypt = async () => {
    setError(null);
    setLoading(true);
    setOutput(null);
    setCopied(false);
    
    try {
      if (!pubKeyInput.trim() || !message.trim()) {
        throw new Error("Public Key and Message are required.");
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
          if (!pubKeyData.n || !pubKeyData.e) throw new Error("Missing n or e");
        } catch (e) {
          throw new Error("Invalid Public Key JSON format.");
        }
      }

      const nBig = BigInt(pubKeyData.n);
      const keyBits = nBig.toString(2).length;
      const keyBytes = Math.floor((keyBits + 7) / 8); 
      const maxSegBytes = useOAEP ? (keyBytes - 2 * 32 - 2) : (keyBytes - 1);

      if (maxSegBytes <= 0) {
        throw new Error("Key size too small for OAEP/SHA-256.");
      }

      const segments = segmentMessage(message, maxSegBytes);
      const encryptedSegments: string[] = [];

      const pubJwk = useOAEP ? dictToPubJwk(pubKeyData.n, pubKeyData.e) : null;

      for (const seg of segments) {
        if (useOAEP && pubJwk) {
            encryptedSegments.push(await encryptSegmentOAEP(seg, pubJwk));
        } else {
            encryptedSegments.push(encryptSegmentTextbook(seg, pubKeyData.n, pubKeyData.e));
        }
      }

      const result = {
        segments: encryptedSegments,
        oaep: useOAEP,
        num_segments: segments.length,
        key_bits: keyBits,
        message_sha256: await sha256(message),
        timestamp: new Date().toISOString()
      };

      setOutput(result);
      
      const keyName = selectedWalletKeyId ? keys.find(k => k.id === selectedWalletKeyId)?.name : undefined;
      addHistory({
        type: "Encrypt",
        details: {
          message: message,
          output: "Encrypted JSON (" + segments.length + " segments)",
          keyName: keyName,
          status: "Success"
        }
      });

    } catch (e: any) {
      setError(e.message);
      addHistory({
        type: "Encrypt",
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
      setPubKeyInput(JSON.stringify(k.keys.public, null, 2));
    } else {
      setSelectedWalletKeyId("");
      setPubKeyInput("");
    }
  };

  const handleCopy = () => {
    if (output) {
      navigator.clipboard.writeText(JSON.stringify(output, null, 2));
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    }
  };

  const clearAll = () => {
      setSelectedWalletKeyId("");
      setPubKeyInput("");
      setMessage("");
      setOutput(null);
      setError(null);
  };

  return (
    <div className="space-y-6">
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <FadeIn className="space-y-6">
          <Card>
            <div className="flex justify-between items-center mb-4">
                <h2 className="text-xl font-semibold text-slate-100 flex items-center gap-2">
                    <Lock className="w-5 h-5 text-indigo-400" /> 1. Public Key
                </h2>
                <div className="flex gap-2 items-center">
                    <FileUpload onFileSelect={(data) => { setPubKeyInput(data); setSelectedWalletKeyId(""); }} label="Load JSON/PEM" accept=".json,.pem,.txt" />
                </div>
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
                <div className="w-full h-32 bg-slate-900 border border-emerald-500/30 rounded-lg p-4 flex flex-col justify-center items-center text-center">
                  <span className="text-emerald-400 font-medium mb-2">Wallet Key Selected</span>
                  <span className="text-slate-300 text-sm">{keys.find(k => k.id === selectedWalletKeyId)?.name}</span>
                  <button onClick={() => setSelectedWalletKeyId("")} className="mt-3 text-xs text-indigo-400 hover:underline">Show Raw / Edit</button>
                </div>
              ) : (
                <textarea
                  value={pubKeyInput}
                  onChange={(e) => { setPubKeyInput(e.target.value); setSelectedWalletKeyId(""); }}
                  placeholder='Paste Public Key JSON or PEM...'
                  className="w-full h-32 bg-slate-950 border border-slate-700 rounded-lg p-3 text-xs font-mono text-slate-300 focus:ring-2 focus:ring-indigo-500 focus:outline-none transition-colors resize-none"
                />
              )}
            </div>
          </Card>

          <Card>
            <div className="flex justify-between items-center mb-4">
                <h2 className="text-xl font-semibold text-slate-100 flex items-center gap-2">
                    <FileJson className="w-5 h-5 text-indigo-400" /> 2. Message
                </h2>
                 <FileUpload onFileSelect={setMessage} label="Load Text" accept=".txt,.json,.md" />
            </div>
            <textarea
              value={message}
              onChange={(e) => setMessage(e.target.value)}
              placeholder="Type your secret message here..."
              className="w-full h-32 bg-slate-950 border border-slate-700 rounded-lg p-3 text-sm text-slate-300 focus:ring-2 focus:ring-indigo-500 focus:outline-none transition-colors resize-none"
            />
          </Card>
        </FadeIn>

        <FadeIn delay={0.1} className="flex flex-col gap-6">
            <Card>
                <div className="flex justify-between items-center mb-4">
                    <h2 className="text-xl font-semibold text-slate-100 flex items-center gap-2">
                        <Info className="w-5 h-5 text-indigo-400" /> 3. Options
                    </h2>
                    <button onClick={clearAll} className="text-xs text-slate-500 hover:text-red-400 flex items-center gap-1">
                        <Trash2 className="w-3 h-3" /> Clear All
                    </button>
                </div>
                
                <div className="space-y-4">
                    <div className="flex items-center justify-between p-4 bg-slate-950 rounded-lg border border-slate-800 hover:border-slate-700 transition-colors">
                        <div>
                            <span className="text-sm font-medium text-slate-200">OAEP Padding</span>
                            <p className="text-xs text-slate-500 mt-1">Recommended for security</p>
                        </div>
                        <label className="relative inline-flex items-center cursor-pointer">
                            <input 
                                type="checkbox" 
                                checked={useOAEP} 
                                onChange={(e) => setUseOAEP(e.target.checked)}
                                className="sr-only peer" 
                            />
                            <div className="w-11 h-6 bg-slate-700 peer-focus:outline-none peer-focus:ring-2 peer-focus:ring-indigo-500 rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-gray-300 after:border after:rounded-full after:h-5 after:w-5 after:transition-all peer-checked:bg-indigo-600"></div>
                        </label>
                    </div>

                    {!useOAEP && (
                        <div className="p-4 bg-amber-500/10 border border-amber-500/20 rounded-lg flex gap-3 items-start">
                            <AlertTriangle className="w-5 h-5 text-amber-500 flex-shrink-0" />
                            <p className="text-xs text-amber-200/80">
                                <strong>Textbook RSA</strong> is insecure and should only be used for educational demonstrations.
                            </p>
                        </div>
                    )}
                </div>

                <NeonButton
                    onClick={handleEncrypt}
                    disabled={loading || !pubKeyInput || !message}
                    className="w-full mt-6"
                >
                    {loading ? "Encrypting..." : "Encrypt Message"}
                </NeonButton>

                {error && (
                    <div className="mt-4 p-3 bg-red-500/10 border border-red-500/20 rounded-lg text-xs text-red-200">
                        {error}
                    </div>
                )}
            </Card>

            {output && (
                <Card className="flex-1 flex flex-col border-emerald-500/30">
                    <div className="flex justify-between items-center mb-2">
                        <h2 className="text-lg font-semibold text-emerald-400">Encrypted Output</h2>
                        <button 
                            onClick={handleCopy} 
                            className="p-1.5 hover:bg-slate-800 rounded text-slate-400 hover:text-white transition-colors"
                            title="Copy JSON"
                        >
                            {copied ? <Check className="w-4 h-4 text-emerald-400" /> : <Copy className="w-4 h-4" />}
                        </button>
                    </div>
                    
                    <pre className="flex-1 bg-slate-950 p-4 rounded-lg text-xs text-emerald-100/80 font-mono overflow-auto border border-slate-900 max-h-[300px]">
                        {JSON.stringify(output, null, 2)}
                    </pre>
                    <div className="mt-4">
                        <NeonButton
                            variant="secondary"
                            onClick={() => {
                                const blob = new Blob([JSON.stringify(output, null, 2)], { type: "application/json" });
                                const url = URL.createObjectURL(blob);
                                const a = document.createElement("a");
                                a.href = url;
                                a.download = `Encrypted_Message_${new Date().toISOString().replace(/[:.]/g, "-")}.json`;
                                a.click();
                            }}
                            className="w-full"
                        >
                            <Download className="w-4 h-4" /> Download JSON
                        </NeonButton>
                    </div>
                </Card>
            )}
        </FadeIn>
      </div>
    </div>
  );
}
