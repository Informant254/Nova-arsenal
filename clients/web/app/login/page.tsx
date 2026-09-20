'use client';

import { FormEvent, useState } from 'react';
import { useRouter, useSearchParams } from 'next/navigation';

export default function LoginPage() {
  const router = useRouter();
  const searchParams = useSearchParams();
  const [mode, setMode] = useState<'login' | 'register'>('login');
  const [email, setEmail] = useState('');
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  async function submit(event: FormEvent) {
    event.preventDefault();
    setLoading(true);
    setError('');

    try {
      if (mode === 'register') {
        const register = await fetch('/api/nova/auth/register', {
          method: 'POST',
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify({ email, username, password }),
        });

        if (!register.ok) {
          const data = await register.json().catch(() => ({}));
          throw new Error(data.detail || 'Could not create account');
        }
      }

      const loginResponse = await fetch('/api/auth/login', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ email, password }),
      });

      if (!loginResponse.ok) {
        const data = await loginResponse.json().catch(() => ({}));
        throw new Error(data.detail || 'Invalid email or password');
      }

      window.localStorage.removeItem('nova_chat_session');
      const next = searchParams.get('next');
      const safeNext =
        next && next.startsWith('/') && !next.startsWith('//') && !next.includes('\\')
          ? next
          : '/';
      router.replace(safeNext);
      router.refresh();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Authentication failed');
    } finally {
      setLoading(false);
    }
  }

  return (
    <main className="grid min-h-screen place-items-center bg-[#070a0f] p-5 text-zinc-100">
      <div className="w-full max-w-md">
        <div className="mb-8 text-center">
          <div className="mx-auto mb-4 grid h-12 w-12 place-items-center rounded-2xl border border-emerald-400/20 bg-emerald-400/10 text-lg font-semibold text-emerald-300">
            N
          </div>
          <h1 className="text-2xl font-semibold tracking-tight">Nova-Arsenal</h1>
          <p className="mt-2 text-sm text-zinc-500">
            {mode === 'login' ? 'Sign in to your research workspace.' : 'Create your local Nova account.'}
          </p>
        </div>

        <form onSubmit={submit} className="panel space-y-5 p-6">
          {error && (
            <div className="rounded-xl border border-red-400/20 bg-red-400/5 p-3 text-sm text-red-300">
              {error}
            </div>
          )}

          {mode === 'register' && (
            <Field label="Username">
              <input
                value={username}
                onChange={(event) => setUsername(event.target.value)}
                minLength={3}
                required
                autoComplete="username"
                className="w-full rounded-xl border border-white/10 bg-black/20 px-3 py-2.5 text-sm outline-none focus:border-emerald-400/30 focus:ring-2 focus:ring-emerald-400/10"
              />
            </Field>
          )}

          <Field label="Email">
            <input
              type="email"
              value={email}
              onChange={(event) => setEmail(event.target.value)}
              required
              autoComplete="email"
              className="w-full rounded-xl border border-white/10 bg-black/20 px-3 py-2.5 text-sm outline-none focus:border-emerald-400/30 focus:ring-2 focus:ring-emerald-400/10"
            />
          </Field>

          <Field label="Password">
            <input
              type="password"
              value={password}
              onChange={(event) => setPassword(event.target.value)}
              minLength={8}
              required
              autoComplete={mode === 'login' ? 'current-password' : 'new-password'}
              className="w-full rounded-xl border border-white/10 bg-black/20 px-3 py-2.5 text-sm outline-none focus:border-emerald-400/30 focus:ring-2 focus:ring-emerald-400/10"
            />
          </Field>

          <button
            type="submit"
            disabled={loading}
            className="w-full rounded-xl bg-emerald-400 px-4 py-2.5 text-sm font-medium text-black transition hover:bg-emerald-300 disabled:opacity-50"
          >
            {loading
              ? mode === 'login'
                ? 'Signing in…'
                : 'Creating account…'
              : mode === 'login'
                ? 'Sign in'
                : 'Create account'}
          </button>

          <button
            type="button"
            onClick={() => {
              setMode((current) => (current === 'login' ? 'register' : 'login'));
              setError('');
            }}
            className="w-full text-sm text-zinc-500 transition hover:text-zinc-300"
          >
            {mode === 'login'
              ? 'No account yet? Create one'
              : 'Already have an account? Sign in'}
          </button>
        </form>
      </div>
    </main>
  );
}

function Field({
  label,
  children,
}: {
  label: string;
  children: React.ReactNode;
}) {
  return (
    <label className="block">
      <span className="mb-2 block text-xs font-medium uppercase tracking-wider text-zinc-500">
        {label}
      </span>
      {children}
    </label>
  );
}
