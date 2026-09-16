import "./globals.css";
import { SocProvider } from "../lib/socContext";

export const metadata = {
  title: "CyberTwin | Enterprise SOC/SIEM Command Console",
  description: "Enterprise Digital Twin Network Security Platform",
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body className="bg-slate-100 antialiased overflow-hidden">
        <SocProvider>
          {children}
        </SocProvider>
      </body>
    </html>
  );
}