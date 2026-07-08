"use client";

import {
  createContext,
  ReactNode,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useRef,
  useState,
} from "react";

export type TabId =
  | "home"
  | "keygen"
  | "encrypt"
  | "decrypt"
  | "sign"
  | "verify"
  | "network"
  | "history";

const TAB_IDS: TabId[] = [
  "home",
  "keygen",
  "encrypt",
  "decrypt",
  "sign",
  "verify",
  "network",
  "history",
];

interface VerifyHandoff {
  message: string;
  signature: string;
}

interface WorkbenchContextType {
  activeTab: TabId;
  selectTab: (id: TabId) => void;
  /** Jump to Decrypt with an encrypted payload prefilled. */
  sendToDecrypt: (payloadJson: string) => void;
  consumeDecryptHandoff: () => string | null;
  /** Jump to Verify with the message and signature prefilled. */
  sendToVerify: (handoff: VerifyHandoff) => void;
  consumeVerifyHandoff: () => VerifyHandoff | null;
}

const WorkbenchContext = createContext<WorkbenchContextType | undefined>(undefined);

export function WorkbenchProvider({ children }: { children: ReactNode }) {
  const [activeTab, setActiveTab] = useState<TabId>("home");
  const decryptHandoff = useRef<string | null>(null);
  const verifyHandoff = useRef<VerifyHandoff | null>(null);

  // Restore the last tab on load. Persisting happens in selectTab, not in an
  // effect keyed on activeTab: a mount-time write would race this read under
  // React StrictMode and clobber the saved value with the default.
  useEffect(() => {
    const savedTab = window.localStorage.getItem("crypticcomm-active-tab");
    if (savedTab && TAB_IDS.includes(savedTab as TabId)) {
      setActiveTab(savedTab as TabId);
    }
  }, []);

  const selectTab = useCallback((id: TabId) => {
    setActiveTab(id);
    window.localStorage.setItem("crypticcomm-active-tab", id);
    window.scrollTo(0, 0);
  }, []);

  const sendToDecrypt = useCallback(
    (payloadJson: string) => {
      decryptHandoff.current = payloadJson;
      selectTab("decrypt");
    },
    [selectTab]
  );

  const consumeDecryptHandoff = useCallback(() => {
    const payload = decryptHandoff.current;
    decryptHandoff.current = null;
    return payload;
  }, []);

  const sendToVerify = useCallback(
    (handoff: VerifyHandoff) => {
      verifyHandoff.current = handoff;
      selectTab("verify");
    },
    [selectTab]
  );

  const consumeVerifyHandoff = useCallback(() => {
    const handoff = verifyHandoff.current;
    verifyHandoff.current = null;
    return handoff;
  }, []);

  const value = useMemo(
    () => ({
      activeTab,
      selectTab,
      sendToDecrypt,
      consumeDecryptHandoff,
      sendToVerify,
      consumeVerifyHandoff,
    }),
    [activeTab, selectTab, sendToDecrypt, consumeDecryptHandoff, sendToVerify, consumeVerifyHandoff]
  );

  return <WorkbenchContext.Provider value={value}>{children}</WorkbenchContext.Provider>;
}

export function useWorkbench() {
  const context = useContext(WorkbenchContext);
  if (!context) {
    throw new Error("useWorkbench must be used within a WorkbenchProvider");
  }
  return context;
}
