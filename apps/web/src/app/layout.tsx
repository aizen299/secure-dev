import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "SecureOps",
  description:
    "Unified DevSecOps platform: normalize, correlate, score, remediate, and gate security findings.",
};

export default function RootLayout({
  children,
}: Readonly<{ children: React.ReactNode }>) {
  return (
    <html lang="en">
      <body className="min-h-screen antialiased">{children}</body>
    </html>
  );
}
