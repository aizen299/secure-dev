import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  reactStrictMode: true,
  // Next generates AGENTS.md and a CLAUDE.md pointing at it inside this
  // package. This repository already has a governing CLAUDE.md at its root, and
  // a second one two directories down is a file that will eventually be read as
  // authoritative by someone -- or by something. Off.
  agentRules: false,
  // Emit a self-contained server bundle so the runtime image ships no toolchain.
  output: "standalone",
  // The dashboard renders security findings. It must never be framed, and it
  // must not leak referrers to third parties. See CLAUDE.md §15.
  poweredByHeader: false,
  async headers() {
    return [
      {
        source: "/:path*",
        headers: [
          { key: "X-Content-Type-Options", value: "nosniff" },
          { key: "X-Frame-Options", value: "DENY" },
          { key: "Referrer-Policy", value: "no-referrer" },
        ],
      },
    ];
  },
};

export default nextConfig;
