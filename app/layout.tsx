import type { Metadata, Viewport } from "next";
import { GeistSans } from "geist/font/sans";
import { GeistMono } from "geist/font/mono";
import favicon from "@/assets/favicon.png";
import "@/styles/globals.css";

export const metadata: Metadata = {
  metadataBase: new URL("https://crypticcomm.vercel.app"),
  title: {
    default: "CrypticComm",
    template: "%s | CrypticComm",
  },
  description:
    "An RSA workspace that runs entirely in your browser: key generation, OAEP encryption, RSA-PSS signatures, an encrypted key wallet, and peer-to-peer encrypted chat.",
  keywords: [
    "CrypticComm",
    "RSA",
    "cryptography",
    "Web Crypto API",
    "WebRTC",
    "peer to peer",
    "Next.js",
  ],
  applicationName: "CrypticComm",
  icons: {
    icon: [{ url: favicon.src, type: "image/png" }],
    shortcut: [{ url: favicon.src, type: "image/png" }],
    apple: [{ url: favicon.src, type: "image/png" }],
  },
  openGraph: {
    title: "CrypticComm",
    description:
      "Learn RSA by using it: generate keys, encrypt, sign, verify, and chat over an encrypted peer connection, all in the browser.",
    url: "https://crypticcomm.vercel.app",
    siteName: "CrypticComm",
    locale: "en_GB",
    type: "website",
  },
  twitter: {
    card: "summary_large_image",
    title: "CrypticComm",
    description:
      "Learn RSA by using it: generate keys, encrypt, sign, verify, and chat over an encrypted peer connection, all in the browser.",
  },
};

export const viewport: Viewport = {
  themeColor: "#0a0a0e",
  colorScheme: "dark",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html
      lang="en"
      className={`${GeistSans.variable} ${GeistMono.variable}`}
      suppressHydrationWarning
    >
      <body className="font-sans antialiased">{children}</body>
    </html>
  );
}
