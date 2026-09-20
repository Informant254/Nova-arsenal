'use client';

import { RefreshCw } from 'lucide-react';
import { useCallback, useEffect, useState } from 'react';

import { novaFetch } from '@/lib/nova-api';

type ProviderRow = {
  provider: string;
  configured: boolean;
  requires_key: boolean;
  key_env: string[];
  default_model: string;
  has_key: boolean;
  key_hint: string;
};

type UserProfile = {
  role: 'viewer' | 'analyst' | 'admin';
};

type ByokStatus = {
  primary: { provider: string; model: string; has_key: boolean };
  fallbacks: { provider: string; model: string; has_key: boolean }[];
  active_providers: string[];
  env_keys_detected: string[];
  provider_catalog: ProviderRow[];
};

export default function SettingsPage() {
  const [status, setStatus] = useState<ByokStatus | null>(null);
  const [profile, setProfile] = useState<UserProfile | null>(null);
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(true);
  const [reloading, setReloading] = useState(false);

  const load = useCallback(async () => {
    setLoading(true);
    setError('');
    try {
      const [modelStatus, userProfile] = await Promise.all([
        novaFetch<ByokStatus>('llm/status'),
        novaFetch<UserProfile>('auth/me'),
      ]);
      setStatus(modelStatus);
      setProfile(userProfile);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Could not load model status');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  async function reload() {
    setReloading(true);
    setError('');
    try {
      await novaFetch('llm/reload', { method: 'POST' });
      await load();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Reload failed');
    } finally {
      setReloading(false);
    }
  }

  return (
    <main className="p-5 md:p-8 lg:p-10">
      <div className="mx-auto max-w-6xl">
        <div className="mb-8 flex flex-col gap-4 sm:flex-row sm:items-end sm:justify-between">
          <div>
            <p className="mb-2 text-xs font-medium uppercase tracking-[0.25em] text-emerald-400">
              Model stack
            </p>
            <h1 className="text-3xl font-semibold">Models</h1>
            <p className="mt-3 max-w-2xl text-sm leading-6 text-zinc-500">
              Provider status is read from Nova&apos;s runtime. Full secrets are never returned to
              the dashboard.
            </p>
          </div>
          <div className="flex gap-2">
            <button
              onClick={() => void load()}
              className="inline-flex items-center gap-2 rounded-xl border border-white/10 px-3 py-2 text-sm text-zinc-400 hover:bg-white/5 hover:text-white"
            >
              <RefreshCw size={15} />
              Refresh
            </button>
            {profile && profile.role !== 'viewer' && (
              <button
                onClick={() => void reload()}
                disabled={reloading}
                className="rounded-xl bg-emerald-400 px-4 py-2 text-sm font-medium text-black hover:bg-emerald-300 disabled:opacity-50"
              >
                {reloading ? 'Reloading…' : 'Reload config'}
              </button>
            )}
          </div>
        </div>

        {error && (
          <div className="mb-5 rounded-xl border border-red-400/20 bg-red-400/5 p-4 text-sm text-red-300">
            {error}
          </div>
        )}

        {loading ? (
          <div className="panel p-8 text-sm text-zinc-500">Loading model stack…</div>
        ) : status ? (
          <>
            <div className="grid gap-4 md:grid-cols-2">
              <section className="panel p-5">
                <div className="text-xs uppercase tracking-wider text-zinc-500">Primary</div>
                <div className="mt-3 text-xl font-medium text-emerald-200">
                  {status.primary.provider + ' / ' + status.primary.model}
                </div>
                <div className="mt-2 text-xs text-zinc-500">
                  {status.primary.has_key || status.primary.provider === 'ollama' || status.primary.provider === 'local'
                    ? 'Ready or local'
                    : 'Credential not detected'}
                </div>
              </section>

              <section className="panel p-5">
                <div className="text-xs uppercase tracking-wider text-zinc-500">Runtime providers</div>
                <div className="mt-3 flex flex-wrap gap-2">
                  {status.active_providers.length ? (
                    status.active_providers.map((provider) => (
                      <span
                        key={provider}
                        className="rounded-full border border-white/10 bg-white/5 px-3 py-1 text-xs text-zinc-300"
                      >
                        {provider}
                      </span>
                    ))
                  ) : (
                    <span className="text-sm text-zinc-500">None active</span>
                  )}
                </div>
                <div className="mt-3 text-xs text-zinc-600">
                  Environment credentials detected: {status.env_keys_detected.join(', ') || 'none'}
                </div>
              </section>
            </div>

            <section className="panel mt-6 overflow-hidden">
              <div className="border-b border-white/10 px-5 py-4">
                <h2 className="font-medium">Provider catalog</h2>
                <p className="mt-1 text-xs text-zinc-500">
                  Defaults are fallbacks only. Environment or account configuration wins.
                </p>
              </div>
              <div className="overflow-x-auto">
                <table className="w-full min-w-[680px] text-left text-sm">
                  <thead className="bg-black/20 text-xs uppercase tracking-wider text-zinc-600">
                    <tr>
                      <th className="px-5 py-3">Provider</th>
                      <th className="px-5 py-3">Credential</th>
                      <th className="px-5 py-3">Default model</th>
                      <th className="px-5 py-3">Environment</th>
                    </tr>
                  </thead>
                  <tbody>
                    {status.provider_catalog.map((provider) => (
                      <tr key={provider.provider} className="border-t border-white/5">
                        <td className="px-5 py-4 font-medium">{provider.provider}</td>
                        <td className="px-5 py-4">
                          {!provider.requires_key ? (
                            <span className="text-emerald-300">local / no key</span>
                          ) : provider.has_key ? (
                            <span className="text-emerald-300">
                              detected {provider.key_hint ? '(' + provider.key_hint + ')' : ''}
                            </span>
                          ) : (
                            <span className="text-zinc-600">not set</span>
                          )}
                        </td>
                        <td className="px-5 py-4 text-zinc-400">{provider.default_model}</td>
                        <td className="px-5 py-4 font-mono text-xs text-zinc-600">
                          {provider.key_env.join(', ') || '—'}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </section>

            <section className="panel mt-6 p-5">
              <h2 className="font-medium">Configuration</h2>
              <p className="mt-2 text-sm leading-6 text-zinc-500">
                Set provider credentials and model overrides in the server environment or
                <code className="mx-1 rounded bg-black/30 px-1.5 py-0.5 text-zinc-300">.env</code>.
                Useful overrides include
                <code className="mx-1 rounded bg-black/30 px-1.5 py-0.5 text-zinc-300">LLM_PROVIDER</code>
                and
                <code className="mx-1 rounded bg-black/30 px-1.5 py-0.5 text-zinc-300">LLM_MODEL</code>.
                The dashboard intentionally does not accept or display full secret keys.
              </p>
            </section>
          </>
        ) : (
          <div className="panel p-8 text-sm text-zinc-500">No model status available.</div>
        )}
      </div>
    </main>
  );
}
