import "./globals.css";
import { SocProvider } from "../lib/socContext";
import GlobalModalOverlays from "../components/GlobalModalOverlays";

export const metadata = {
  title: "CyberTwin | Enterprise SOC/SIEM Command Console",
  description: "Enterprise Digital Twin Network Security Platform",
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en" className="dark">
      <body className="bg-obsidian text-slate-200 antialiased overflow-hidden font-sans">
        <SocProvider>
          {children}
          <GlobalModalOverlays />
        </SocProvider>
      </body>
    </html>
  );
}