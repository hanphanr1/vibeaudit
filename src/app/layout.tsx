import type { Metadata } from 'next';
import type { ReactNode } from 'react';
import './studio.css';

export const metadata: Metadata = { title:'VibeAudit / Security Studio',description:'Read-only source security checks for Next.js, Supabase and Stripe.' };
export default function Layout({ children }: { children: ReactNode }) {
  return <html lang="en"><body>{children}</body></html>;
}
