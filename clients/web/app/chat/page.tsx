'use client';

import { MessageSquarePlus, Send, Trash2 } from 'lucide-react';
import { FormEvent, useCallback, useEffect, useRef, useState } from 'react';
import Markdown from 'react-markdown';

import { novaFetch } from '@/lib/nova-api';

type Message = {
  id: string;
  role: 'user' | 'assistant';
  content: string;
  intent?: string;
};

type ChatSession = {
  session_id: string;
  title: string;
  created_at: string;
  updated_at: string;
  message_count: number;
};

type LlmStatus = {
  primary: { provider: string; model: string; has_key: boolean };
  active_providers: string[];
};

type HistoryResponse = {
  session_id: string;
  messages: Array<{
    role: 'user' | 'assistant';
    content: string;
    created_at?: string;
  }>;
};

export default function ChatPage() {
  const [messages, setMessages] = useState<Message[]>([]);
  const [sessions, setSessions] = useState<ChatSession[]>([]);
  const [input, setInput] = useState('');
  const [streaming, setStreaming] = useState(false);
  const [loadingHistory, setLoadingHistory] = useState(false);
  const [sessionId, setSessionId] = useState('');
  const [brain, setBrain] = useState<LlmStatus | null>(null);
  const [error, setError] = useState('');
  const bottomRef = useRef<HTMLDivElement | null>(null);

  const loadSessions = useCallback(async () => {
    try {
      const data = await novaFetch<{ sessions: ChatSession[] }>('chat/sessions');
      setSessions(data.sessions || []);
    } catch {
      setSessions([]);
    }
  }, []);

  const loadHistory = useCallback(async (id: string) => {
    if (!id) return;
    setLoadingHistory(true);
    setError('');
    try {
      const data = await novaFetch<HistoryResponse>(
        'chat/sessions/' + encodeURIComponent(id) + '/history',
      );
      setMessages(
        (data.messages || []).map((message, index) => ({
          id: id + '-' + index + '-' + message.role,
          role: message.role,
          content: message.content,
        })),
      );
    } catch (err) {
      const detail = err instanceof Error ? err.message : '';
      // A brand-new client-generated session does not exist server-side until
      // the first message is sent. That is an empty state, not an error.
      if (detail.includes('404') || detail.toLowerCase().includes('not found')) {
        setMessages([]);
      } else {
        setError(detail || 'Could not load conversation history');
      }
    } finally {
      setLoadingHistory(false);
    }
  }, []);

  useEffect(() => {
    const stored = window.localStorage.getItem('nova_chat_session');
    const id = stored || crypto.randomUUID();
    window.localStorage.setItem('nova_chat_session', id);
    setSessionId(id);
    void loadSessions();
    void novaFetch<LlmStatus>('llm/status').then(setBrain).catch(() => setBrain(null));
  }, [loadSessions]);

  useEffect(() => {
    if (sessionId) void loadHistory(sessionId);
  }, [sessionId, loadHistory]);

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: streaming ? 'auto' : 'smooth' });
  }, [messages, streaming]);

  function selectSession(id: string) {
    if (streaming || id === sessionId) return;
    window.localStorage.setItem('nova_chat_session', id);
    setSessionId(id);
    setInput('');
  }

  function newConversation() {
    if (streaming) return;
    const id = crypto.randomUUID();
    window.localStorage.setItem('nova_chat_session', id);
    setSessionId(id);
    setMessages([]);
    setInput('');
    setError('');
  }

  async function deleteConversation(id: string) {
    if (streaming) return;
    try {
      await novaFetch('chat/sessions/' + encodeURIComponent(id), { method: 'DELETE' });
      await loadSessions();
      if (id === sessionId) newConversation();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Could not delete conversation');
    }
  }

  async function send(event: FormEvent) {
    event.preventDefault();
    const message = input.trim();
    if (!message || !sessionId || streaming) return;

    const userId = crypto.randomUUID();
    const assistantId = crypto.randomUUID();

    setError('');
    setInput('');
    setStreaming(true);
    setMessages((current) => [
      ...current,
      { id: userId, role: 'user', content: message },
      { id: assistantId, role: 'assistant', content: '' },
    ]);

    try {
      const response = await fetch('/api/nova/chat/stream', {
        method: 'POST',
        headers: {
          'content-type': 'application/json',
          accept: 'text/event-stream',
        },
        body: JSON.stringify({
          message,
          session_id: sessionId,
          stream: true,
        }),
      });

      if (response.status === 401) {
        window.location.assign('/login');
        return;
      }
      if (!response.ok || !response.body) {
        throw new Error('Nova API returned HTTP ' + response.status);
      }

      const reader = response.body.getReader();
      const decoder = new TextDecoder();
      let buffer = '';

      while (true) {
        const result = await reader.read();
        if (result.done) break;

        buffer += decoder.decode(result.value, { stream: true });
        const events = buffer.split('\n\n');
        buffer = events.pop() || '';

        for (const eventBlock of events) {
          const dataLine = eventBlock
            .split('\n')
            .find((line) => line.startsWith('data: '));
          if (!dataLine) continue;

          try {
            const eventData = JSON.parse(dataLine.slice(6));

            if (eventData.type === 'chunk' && eventData.content) {
              setMessages((current) =>
                current.map((entry) =>
                  entry.id === assistantId
                    ? { ...entry, content: entry.content + eventData.content }
                    : entry,
                ),
              );
            }

            if (eventData.type === 'intent' && eventData.intent) {
              setMessages((current) =>
                current.map((entry) =>
                  entry.id === assistantId
                    ? { ...entry, intent: eventData.intent }
                    : entry,
                ),
              );
            }
          } catch {
            // Ignore malformed partial SSE fragments.
          }
        }
      }

      await loadSessions();
    } catch (err) {
      const detail = err instanceof Error ? err.message : 'Unknown connection error';
      setMessages((current) =>
        current.map((entry) =>
          entry.id === assistantId
            ? { ...entry, content: 'Connection error: ' + detail }
            : entry,
        ),
      );
    } finally {
      setStreaming(false);
    }
  }

  return (
    <main className="flex h-[calc(100vh-65px)] min-h-0 md:h-screen">
      <aside className="hidden w-72 shrink-0 border-r border-white/10 bg-black/10 lg:flex lg:flex-col">
        <div className="border-b border-white/10 p-4">
          <button
            onClick={newConversation}
            className="flex w-full items-center justify-center gap-2 rounded-xl bg-emerald-400 px-3 py-2.5 text-sm font-medium text-black transition hover:bg-emerald-300"
          >
            <MessageSquarePlus size={16} />
            New conversation
          </button>
        </div>

        <div className="min-h-0 flex-1 overflow-y-auto p-3">
          <div className="mb-2 px-2 text-[10px] uppercase tracking-[0.18em] text-zinc-600">
            Recent
          </div>
          <div className="space-y-1">
            {sessions.length === 0 ? (
              <div className="px-2 py-4 text-xs leading-5 text-zinc-600">
                Conversations appear here after your first message.
              </div>
            ) : (
              sessions.map((session) => {
                const active = session.session_id === sessionId;
                return (
                  <div
                    key={session.session_id}
                    className={[
                      'group flex items-center gap-1 rounded-xl',
                      active ? 'bg-white/[0.07]' : 'hover:bg-white/[0.035]',
                    ].join(' ')}
                  >
                    <button
                      onClick={() => selectSession(session.session_id)}
                      className="min-w-0 flex-1 px-3 py-2.5 text-left"
                    >
                      <div className={active ? 'truncate text-sm text-zinc-100' : 'truncate text-sm text-zinc-400'}>
                        {session.title || 'New Chat'}
                      </div>
                      <div className="mt-1 text-[10px] text-zinc-600">
                        {session.message_count} messages
                      </div>
                    </button>
                    <button
                      onClick={() => void deleteConversation(session.session_id)}
                      aria-label={'Delete ' + (session.title || 'conversation')}
                      className="mr-2 rounded-md p-1.5 text-zinc-700 opacity-0 transition hover:bg-red-400/10 hover:text-red-300 group-hover:opacity-100"
                    >
                      <Trash2 size={13} />
                    </button>
                  </div>
                );
              })
            )}
          </div>
        </div>
      </aside>

      <section className="flex min-w-0 flex-1 flex-col">
        <div className="border-b border-white/10 px-5 py-4 md:px-8">
          <div className="mx-auto flex max-w-5xl items-center justify-between gap-4">
            <div className="min-w-0">
              <div className="flex flex-wrap items-center gap-2">
                <h1 className="font-semibold">Nova chat</h1>
                {brain && (
                  <span className="max-w-[260px] truncate rounded-full border border-emerald-400/15 bg-emerald-400/[0.06] px-2.5 py-1 text-[10px] text-emerald-300">
                    {brain.primary.provider} / {brain.primary.model}
                  </span>
                )}
              </div>
              <p className="mt-1 text-xs text-zinc-500">
                Persistent conversation with runtime model routing.
              </p>
            </div>
            <div className="flex items-center gap-2 lg:hidden">
              {sessions.length > 0 && (
                <select
                  value={sessions.some((session) => session.session_id === sessionId) ? sessionId : ''}
                  onChange={(event) => {
                    if (event.target.value) selectSession(event.target.value);
                  }}
                  disabled={streaming}
                  aria-label="Recent conversations"
                  className="max-w-[150px] rounded-lg border border-white/10 bg-black/30 px-2 py-2 text-xs text-zinc-400 outline-none disabled:opacity-40"
                >
                  <option value="">Recent chats</option>
                  {sessions.map((session) => (
                    <option key={session.session_id} value={session.session_id}>
                      {session.title || 'New Chat'}
                    </option>
                  ))}
                </select>
              )}
              <button
                onClick={newConversation}
                disabled={streaming}
                className="inline-flex items-center gap-2 rounded-lg border border-white/10 px-3 py-2 text-xs text-zinc-400 transition hover:bg-white/5 hover:text-white disabled:opacity-40"
              >
                <MessageSquarePlus size={14} />
                New chat
              </button>
            </div>
          </div>
        </div>

        {error && (
          <div
            className="mx-auto mt-4 w-full max-w-5xl px-5 md:px-8"
            role="alert"
            aria-live="polite"
          >
            <div className="rounded-xl border border-red-400/20 bg-red-400/5 p-3 text-xs text-red-300">
              {error}
            </div>
          </div>
        )}

        <div className="min-h-0 flex-1 overflow-y-auto px-5 py-6 md:px-8">
          <div className="mx-auto max-w-5xl space-y-5">
            {loadingHistory ? (
              <div className="panel p-8 text-center text-sm text-zinc-500">
                Loading conversation…
              </div>
            ) : messages.length === 0 ? (
              <div className="panel mx-auto mt-16 max-w-2xl p-8 text-center">
                <div className="mx-auto mb-5 grid h-12 w-12 place-items-center rounded-2xl bg-emerald-400/10 text-xl text-emerald-300">
                  N
                </div>
                <h2 className="text-xl font-medium">Talk to Nova</h2>
                <p className="mx-auto mt-3 max-w-lg text-sm leading-6 text-zinc-500">
                  Ask for explanations, code review, research planning, architecture help, or analysis.
                  Active security actions remain separately authorization-gated.
                </p>
              </div>
            ) : (
              messages.map((message) => (
                <div
                  key={message.id}
                  className={message.role === 'user' ? 'flex justify-end' : 'flex justify-start'}
                >
                  <div
                    className={[
                      'max-w-[88%] rounded-2xl px-4 py-3 text-sm leading-6 md:max-w-[78%]',
                      message.role === 'user'
                        ? 'bg-emerald-400 text-black'
                        : 'border border-white/10 bg-white/[0.04] text-zinc-200',
                    ].join(' ')}
                  >
                    {message.intent && message.role === 'assistant' && (
                      <div className="mb-2 text-[10px] uppercase tracking-[0.18em] text-zinc-500">
                        {message.intent.replaceAll('_', ' ')}
                      </div>
                    )}
                    {message.role === 'assistant' ? (
                      <div className="nova-markdown">
                        <Markdown
                          components={{
                            a: ({ href, children }) => (
                              <a
                                href={href}
                                target="_blank"
                                rel="noreferrer noopener"
                              >
                                {children}
                              </a>
                            ),
                          }}
                        >
                          {message.content || (streaming ? '…' : '')}
                        </Markdown>
                      </div>
                    ) : (
                      <div className="whitespace-pre-wrap break-words">
                        {message.content}
                      </div>
                    )}
                  </div>
                </div>
              ))
            )}
            <div ref={bottomRef} />
          </div>
        </div>

        <div className="border-t border-white/10 bg-[#070a0f]/95 p-4 backdrop-blur">
          <form onSubmit={send} className="mx-auto flex max-w-5xl items-end gap-3">
            <textarea
              value={input}
              onChange={(event) => setInput(event.target.value)}
              onKeyDown={(event) => {
                if (event.key === 'Enter' && !event.shiftKey) {
                  event.preventDefault();
                  event.currentTarget.form?.requestSubmit();
                }
              }}
              rows={1}
              placeholder="Message Nova…"
              className="min-h-12 max-h-40 flex-1 resize-y rounded-2xl border border-white/10 bg-white/[0.04] px-4 py-3 text-sm text-zinc-100 outline-none transition placeholder:text-zinc-600 focus:border-emerald-400/30 focus:ring-2 focus:ring-emerald-400/10"
            />
            <button
              type="submit"
              disabled={streaming || loadingHistory || !input.trim()}
              className="grid h-12 w-12 shrink-0 place-items-center rounded-2xl bg-emerald-400 text-black transition hover:bg-emerald-300 disabled:cursor-not-allowed disabled:opacity-40"
              aria-label="Send message"
            >
              <Send size={18} />
            </button>
          </form>
        </div>
      </section>
    </main>
  );
}
