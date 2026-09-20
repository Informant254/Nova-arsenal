import type { Metadata } from 'next';
import { Inter } from 'next/font/google';

import { AppShell } from '@/components/app-shell';
import './globals.css';

const inter = Inter({ subsets: ['latin'] });

export const metadata: Metadata = {
  title: 'Nova-Arsenal',
  description: 'AI-assisted security research workspace',
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en">
      <body className={inter.className}>
        <AppShell>{children}</AppShell>
      </body>
    </html>
  );
}
