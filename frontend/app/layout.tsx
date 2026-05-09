import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "EVM Security Atlas",
  description: "Vulnerability intelligence over verified Sourcify contracts",
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en">
      <body className="antialiased">{children}</body>
    </html>
  );
}
