import type { Metadata } from "next";
import { Geist, Geist_Mono } from "next/font/google";
import "./globals.css";

const geistSans = Geist({
  variable: "--font-geist-sans",
  subsets: ["latin"],
});

const geistMono = Geist_Mono({
  variable: "--font-geist-mono",
  subsets: ["latin"],
});

export const metadata: Metadata = {
  title: "VaultCode",
  description: "End-to-end encrypted password manager developed by Aroham Technologies Pvt Ltd (OPC)",
  applicationName: "VaultCode",
  creator: "Aroham Technologies Pvt Ltd (OPC)",
  authors: [{ name: "Aroham Technologies Pvt Ltd (OPC)" }],
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en">
      <body
        className={`${geistSans.variable} ${geistMono.variable} antialiased`}
      >
        <div className="relative min-h-screen">
          {children}
          <div className="pointer-events-none fixed inset-x-0 bottom-0 z-50 p-3 text-center">
            <div className="text-[11px] text-slate-500">
              Developed by Aroham Technologies Pvt Ltd (OPC)
            </div>
          </div>
        </div>
      </body>
    </html>
  );
}
