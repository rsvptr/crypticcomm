"use client";

import { createContext, useContext, useEffect, useState, ReactNode } from "react";
import {
  RSAKeyDict,
  generateKeyName,
  encryptWalletData,
  decryptWalletData,
  walletPayloadNeedsUpgrade,
} from "@/lib/rsa";

export interface StoredKey {
  id: string;
  name: string;
  keys: RSAKeyDict;
  createdAt: number;
}

interface WalletContextType {
  keys: StoredKey[];
  isLocked: boolean;
  hasWallet: boolean;
  unlockWallet: (password: string) => Promise<number>;
  createWallet: (password: string) => Promise<void>;
  lockWallet: () => void;
  saveKey: (key: RSAKeyDict) => Promise<StoredKey>;
  deleteKey: (id: string) => Promise<void>;
  getKey: (id: string) => StoredKey | undefined;
}

const WalletContext = createContext<WalletContextType | undefined>(undefined);

export function WalletProvider({ children }: { children: ReactNode }) {
  const [keys, setKeys] = useState<StoredKey[]>([]);
  const [isLocked, setIsLocked] = useState(true);
  const [hasWallet, setHasWallet] = useState(false);
  const [password, setPassword] = useState<string | null>(null);

  const persistWallet = async (nextKeys: StoredKey[], pwd: string) => {
    const encrypted = await encryptWalletData(nextKeys, pwd);
    localStorage.setItem("cryptic_wallet_enc", encrypted);
  };

  useEffect(() => {
    // Only the encrypted format counts as a wallet. Plaintext wallets from old
    // builds can't be unlocked with a password, so they are ignored here and
    // removed when a new encrypted wallet is created.
    setHasWallet(Boolean(localStorage.getItem("cryptic_wallet_enc")));
  }, []);

  const createWallet = async (pwd: string) => {
    const emptyWallet = await encryptWalletData([], pwd);
    localStorage.setItem("cryptic_wallet_enc", emptyWallet);
    localStorage.removeItem("cryptic_wallet"); // clear old
    setHasWallet(true);
    setIsLocked(false);
    setPassword(pwd);
    setKeys([]);
  };

  const unlockWallet = async (pwd: string): Promise<number> => {
    const stored = localStorage.getItem("cryptic_wallet_enc");
    if (!stored) {
      throw new Error("No wallet exists in this browser yet.");
    }

    let decryptedKeys: StoredKey[];
    try {
      const decrypted = await decryptWalletData(stored, pwd);
      if (!Array.isArray(decrypted)) {
        throw new Error("corrupted");
      }
      decryptedKeys = decrypted;
    } catch {
      throw new Error("Wrong password, or the wallet data is unreadable.");
    }

    // Wallets written with an older, weaker work factor are quietly
    // re-encrypted at the current strength; unlock is the only moment the
    // password is available to do it. Best effort: if the write fails, the
    // wallet still works at its old strength.
    if (walletPayloadNeedsUpgrade(stored)) {
      try {
        await persistWallet(decryptedKeys, pwd);
      } catch {
        // Keep the unlock; the upgrade can happen on a later visit.
      }
    }

    setKeys(decryptedKeys);
    setIsLocked(false);
    setPassword(pwd);
    return decryptedKeys.length;
  };

  const lockWallet = () => {
    setKeys([]);
    setIsLocked(true);
    setPassword(null);
  };

  const saveKey = async (keyData: RSAKeyDict) => {
    if (isLocked || !password)
      throw new Error("The wallet is locked. Unlock it from the header first.");

    const existing = keys.find((key) => key.keys.public.n === keyData.public.n);
    if (existing) {
      throw new Error(`This identity is already saved as "${existing.name}".`);
    }

    const name = await generateKeyName(keyData.public);
    const newKey: StoredKey = {
      id: crypto.randomUUID(),
      name,
      keys: keyData,
      createdAt: Date.now(),
    };

    // Persist first: if the write fails (storage quota, private browsing),
    // in-memory state must not claim the key was saved.
    const updated = [newKey, ...keys];
    await persistWallet(updated, password);
    setKeys(updated);
    return newKey;
  };

  const deleteKey = async (id: string) => {
    if (isLocked || !password)
      throw new Error("The wallet is locked. Unlock it from the header first.");
    const updated = keys.filter((k) => k.id !== id);
    await persistWallet(updated, password);
    setKeys(updated);
  };

  const getKey = (id: string) => keys.find((k) => k.id === id);

  return (
    <WalletContext.Provider
      value={{
        keys,
        isLocked,
        hasWallet,
        unlockWallet,
        createWallet,
        lockWallet,
        saveKey,
        deleteKey,
        getKey,
      }}
    >
      {children}
    </WalletContext.Provider>
  );
}

export function useWallet() {
  const context = useContext(WalletContext);
  if (context === undefined) {
    throw new Error("useWallet must be used within a WalletProvider");
  }
  return context;
}
