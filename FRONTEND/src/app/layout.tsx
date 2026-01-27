import type { Metadata } from "next";
import { Inter } from "next/font/google";
import { ThemeProvider } from "@/components/ThemeProvider";
import { HydrationFix } from "@/components/HydrationFix";
import { Navbar } from "@/components/Navbar";
import "./globals.css";

const inter = Inter({ subsets: ["latin"] });

export const metadata: Metadata = {
  title: "VCINF TECH",
  description: "Soluções Completas em Hardware e Inteligência Fiscal",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="pt-BR" suppressHydrationWarning>
      <body>
        <HydrationFix />
        <ThemeProvider>
          <Navbar />
          <main className={inter.className}>{children}</main>
        </ThemeProvider>
      </body>
    </html>
  );
}

