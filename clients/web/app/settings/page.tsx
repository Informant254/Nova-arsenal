'use client';

import { useCallback, useEffect, useState } from 'react';

type ProviderRow = {
  provider: string;
  configured: boolean;
  requires_key: boolean;
  key_env: string[];
  default_model: string;
  has_key: boolean;
  key_hint: string;
};

type ByokStatus = {
  primary: { provider: string; model: string; has_key: boolean };
  fallbacks: { provider: string; model: string; has_key: boolean }[];
  active_providers: string[];
  env_keys_detected: string[];
  provider_catalog: ProviderRow[];
  how_to: Record<string, string>;
};

const API_BASE =
  process.env.NEXT_PUBLIC_AGENT_API_URL ||
  process.env.AGENT_API_URL ||
  'http://localhost:8000';

export default function SettingsPage() {
  const [status, setStatus] = useState<ByokStatus | null>(null);
  const [error, setError] = useState<string>('');
  const [loading, setLoading] = useState(true);
  const [reloading, setReloading] = useState(false);

  const load = useCallback(async () => {
    setLoading(true);
    setError('');
    try {
      const res = await fetch(`${API_BASE}/api/llm/status`, { cache: 'no-store' });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const data = (await res.json()) as ByokStatus;
      setStatus(data);
    } catch (e) {
      setError(
        e instanceof Error
          ? e.message
          : 'Could not reach agent API. Is Nova running on :8000?'
      );
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    load();
  }, [load]);

  async function reloadConfig() {
    setReloading(true);
    setError('');
    try {
      const res = await fetch(`${API_BASE}/api/llm/reload`, { method: 'POST' });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      await load();
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Reload failed');
    } finally {
      setReloading(false);
    }
  }

  return (
    <div className="min-h-screen p-8 bg-gray-950 text-gray-100">
      <div className="max-w-4xl mx-auto">
        <h1 className="text-3xl font-bold text-emerald-400 mb-2">Settings</h1>
        <p className="text-gray-400 mb-8">
          Bring your own AI subscription — set API keys in <code className="text-emerald-300">.env</code> and
          Nova routes the agent through your providers.
        </p>

        <div className="space-y-6">
          <div className="bg-gray-900 border border-gray-800 rounded-lg shadow p-6">
            <div className="flex items-center justify-between mb-4">
              <h2 className="text-xl font-semibold">LLM / BYOK status</h2>
              <div className="flex gap-2">
                <button
                  onClick={load}
                  className="px-3 py-1.5 text-sm rounded bg-gray-800 hover:bg-gray-700 border border-gray-700"
                >
                  Refresh
                </button>
                <button
                  onClick={reloadConfig}
                  disabled={reloading}
                  className="px-3 py-1.5 text-sm rounded bg-emerald-700 hover:bg-emerald-600 disabled:opacity-50"
                >
                  {reloading ? 'Reloading…' : 'Reload keys'}
                </button>
              </div>
            </div>

            {loading && <p className="text-gray-500">Loading provider status…</p>}
            {error && (
              <p className="text-red-400 mb-4 text-sm">
                {error}
              </p>
            )}

            {status && (
              <div className="space-y-4">
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  <div className="rounded border border-gray-800 p-4">
                    <div className="text-xs uppercase text-gray-500 mb-1">Primary</div>
                    <div className="text-lg font-medium">
                      {status.primary.provider}
                      <span className="text-gray-500"> / {status.primary.model}</span>
                    </div>
                    <div className="text-sm mt-1">
                      {status.primary.has_key ? (
                        <span className="text-emerald-400">Key ready</span>
                      ) : (
                        <span className="text-amber-400">No key (will fail for cloud providers)</span>
                      )}
                    </div>
                  </div>
                  <div className="rounded border border-gray-800 p-4">
                    <div className="text-xs uppercase text-gray-500 mb-1">Active providers</div>
                    <div className="text-sm text-gray-300">
                      {status.active_providers.length
                        ? status.active_providers.join(', ')
                        : 'None configured'}
                    </div>
                    <div className="text-xs text-gray-500 mt-2">
                      Env keys detected: {status.env_keys_detected.join(', ') || 'none'}
                    </div>
                  </div>
                </div>

                <div className="overflow-x-auto">
                  <table className="w-full text-sm">
                    <thead>
                      <tr className="text-left text-gray-500 border-b border-gray-800">
                        <th className="py-2 pr-4">Provider</th>
                        <th className="py-2 pr-4">Key</th>
                        <th className="py-2 pr-4">Env vars</th>
                        <th className="py-2">Default model</th>
                      </tr>
                    </thead>
                    <tbody>
                      {status.provider_catalog.map((p) => (
                        <tr key={p.provider} className="border-b border-gray-900">
                          <td className="py-2 pr-4 font-medium">{p.provider}</td>
                          <td className="py-2 pr-4">
                            {p.provider === 'ollama' ? (
                              <span className="text-emerald-400">local (no key)</span>
                            ) : p.has_key ? (
                              <span className="text-emerald-400">set ({p.key_hint})</span>
                            ) : (
                              <span className="text-gray-500">not set</span>
                            )}
                          </td>
                          <td className="py-2 pr-4 text-gray-400 font-mono text-xs">
                            {p.key_env.join(', ') || '—'}
                          </td>
                          <td className="py-2 text-gray-400">{p.default_model}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            )}
          </div>

          <div className="bg-gray-900 border border-gray-800 rounded-lg shadow p-6">
            <h2 className="text-xl font-semibold mb-3">How to connect your subscription</h2>
            <ol className="list-decimal list-inside space-y-2 text-gray-300 text-sm">
              <li>
                Copy <code className="text-emerald-300">config/.env.example</code> →{' '}
                <code className="text-emerald-300">.env</code>
              </li>
              <li>Paste the API key from your OpenAI / Claude / Gemini / OpenRouter account</li>
              <li>
                Optional: set <code className="text-emerald-300">LLM_PROVIDER=openai</code> and{' '}
                <code className="text-emerald-300">LLM_MODEL=gpt-4o</code>
              </li>
              <li>Restart the agent API (or click Reload keys)</li>
              <li>
                Verify with <code className="text-emerald-300">GET /api/llm/status</code>
              </li>
            </ol>
            <pre className="mt-4 p-4 rounded bg-black/50 text-xs text-emerald-200 overflow-x-auto">
{`# examples
export OPENAI_API_KEY=sk-...
export ANTHROPIC_API_KEY=sk-ant-...
export GOOGLE_API_KEY=...
export OPENROUTER_API_KEY=sk-or-...

export LLM_PROVIDER=anthropic
export LLM_MODEL=claude-sonnet-4-20250514

python -m nova_arsenal.api`}
            </pre>
            <p className="mt-3 text-xs text-gray-500">
              Keys stay on your machine / server env. The dashboard never displays full secrets.
              Platform login (JWT) is separate from LLM provider keys.
            </p>
          </div>
        </div>
      </div>
    </div>
  );
}
