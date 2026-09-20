'use client';

import { Send, Trash2 } from 'lucide-react';
import { FormEvent, useEffect, useRef, useState } from 'react';

type Message = {
  role: 'user' | 'assistant';
  content: string;
  intent?: string;
};

export default function ChatPage() {
  const [messages, setMessages] = useState<Message[]>([]);
  const [input, setInput] = useState('');
  const [streaming, setStreaming] = useState(false);
  const [sessionId, setSessionId] = useState('');
  const bottomRef = useRef<HTMLDivElement | null>(null);

  useEffect(() => {
    const stored = window.localStorage.getItem('nova_chat_session');
    const id = stored || crypto.randomUUID();
    window.localStorage.setItem('nova_chat_session', id);
    setSessionId(id);
  }, []);

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [messages]);

  async function send(event: FormEvent) {
    event.preventDefault();
    const message = input.trim();
    if (!message || !sessionId || streaming) return;

    setInput('');
    setStreaming(true);
    setMessages((current) => [...current, { role: 'user', content: message }]);

    const assistantIndex = messages.length + 1;
    setMessages((current) => [...current, { role: 'assistant', content: '' }]);

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
                current.map((entry, index) =>
                  index === assistantIndex
                    ? { ...entry, content: entry.content + eventData.content }
                    : entry,
                ),
              );
            }

            if (eventData.type === 'intent' && eventData.intent) {
              setMessages((current) =>
                current.map((entry, index) =>
                  index === assistantIndex
                    ? { ...entry, intent: eventData.intent }
                    : entry,
                ),
              );
            }
          } catch {
            // Ignore malformed event fragments; the next complete SSE event can continue.
          }
        }
      }
    } catch (error) {
      const detail = error instanceof Error ? error.message : 'Unknown connection error';
      setMessages((current) =>
        current.map((entry, index) =>
          index === assistantIndex
            ? { ...entry, content: 'Connection error: ' + detail }
            : entry,
        ),
      );
    } finally {
      setStreaming(false);
    }
  }

  function newConversation() {
    const id = crypto.randomUUID();
    window.localStorage.setItem('nova_chat_session', id);
    setSessionId(id);
    setMessages([]);
    setInput('');
  }

  return (
    <main className="flex h-[calc(100vh-65px)] flex-col md:h-screen">
      <div className="border-b border-white/10 px-5 py-4 md:px-8">
        <div className="mx-auto flex max-w-5xl items-center justify-between gap-4">
          <div>
            <h1 className="font-semibold">Nova chat</h1>
            <p className="mt-1 text-xs text-zinc-500">
              Routed through your configured model stack with persistent session context.
            </p>
          </div>
          <button
            onClick={newConversation}
            className="inline-flex items-center gap-2 rounded-lg border border-white/10 px-3 py-2 text-xs text-zinc-400 transition hover:bg-white/5 hover:text-white"
          >
            <Trash2 size={14} />
            New chat
          </button>
        </div>
      </div>

      <div className="min-h-0 flex-1 overflow-y-auto px-5 py-6 md:px-8">
        <div className="mx-auto max-w-5xl space-y-5">
          {messages.length === 0 && (
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
          )}

          {messages.map((message, index) => (
            <div
              key={index}
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
                <div className="whitespace-pre-wrap break-words">
                  {message.content || (streaming && index === messages.length - 1 ? '…' : '')}
                </div>
              </div>
            </div>
          ))}
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
            disabled={streaming || !input.trim()}
            className="grid h-12 w-12 shrink-0 place-items-center rounded-2xl bg-emerald-400 text-black transition hover:bg-emerald-300 disabled:cursor-not-allowed disabled:opacity-40"
            aria-label="Send message"
          >
            <Send size={18} />
          </button>
        </form>
      </div>
    </main>
  );
}
