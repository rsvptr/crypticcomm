import type { Metadata, Viewport } from "next";
import { IBM_Plex_Mono, Space_Grotesk } from "next/font/google";
import favicon from "@/assets/favicon.png";
import "@/styles/globals.css";

const spaceGrotesk = Space_Grotesk({
  subsets: ["latin"],
  variable: "--font-space-grotesk",
  display: "swap",
});

const ibmPlexMono = IBM_Plex_Mono({
  subsets: ["latin"],
  weight: ["400", "500", "600"],
  variable: "--font-ibm-plex-mono",
  display: "swap",
});

export const metadata: Metadata = {
  metadataBase: new URL("https://crypticcomm.vercel.app"),
  title: {
    default: "CrypticComm",
    template: "%s | CrypticComm",
  },
  description:
    "A privacy-first RSA learning suite for key generation, encryption, signatures, wallet storage, and encrypted peer messaging.",
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
      "Learn RSA hands-on with browser-only encryption, signatures, wallet storage, and encrypted WebRTC chat.",
    url: "https://crypticcomm.vercel.app",
    siteName: "CrypticComm",
    locale: "en_GB",
    type: "website",
  },
  twitter: {
    card: "summary_large_image",
    title: "CrypticComm",
    description:
      "Browser-native RSA learning suite with PEM export, wallet storage, and encrypted peer chat.",
  },
};

export const viewport: Viewport = {
  themeColor: "#060816",
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
      className={`${spaceGrotesk.variable} ${ibmPlexMono.variable}`}
      suppressHydrationWarning
    >
      <body className="font-sans antialiased">{children}</body>
    </html>
  );
}
