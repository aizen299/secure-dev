import type { Metadata } from "next";
import { Inter, JetBrains_Mono } from "next/font/google";
import { TooltipProvider } from "@/components/ui/tooltip";
import { ThemeScript } from "@/components/shell/theme";
import "./globals.css";

// Two families and no more. Inter for the interface, a real mono for anything
// a person might copy or compare character by character -- fingerprints, CVE
// ids, image references, commit SHAs. Mixing a third face is the fastest way
// to lose the typographic discipline the rest of this design depends on.
const inter = Inter({
  subsets: ["latin"],
  variable: "--font-inter",
  display: "swap",
});

const mono = JetBrains_Mono({
  subsets: ["latin"],
  variable: "--font-geist-mono",
  display: "swap",
});

export const metadata: Metadata = {
  title: {
    default: "SecureOps",
    template: "%s · SecureOps",
  },
  description:
    "Turns fragmented security scanner output into one contextual security decision.",
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en" className={`${inter.variable} ${mono.variable}`} suppressHydrationWarning>
      <head>
        <ThemeScript />
      </head>
      <body className="min-h-screen antialiased">
        <TooltipProvider delayDuration={200} skipDelayDuration={300}>
          {children}
        </TooltipProvider>
      </body>
    </html>
  );
}
