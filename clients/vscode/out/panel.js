"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || (function () {
    var ownKeys = function(o) {
        ownKeys = Object.getOwnPropertyNames || function (o) {
            var ar = [];
            for (var k in o) if (Object.prototype.hasOwnProperty.call(o, k)) ar[ar.length] = k;
            return ar;
        };
        return ownKeys(o);
    };
    return function (mod) {
        if (mod && mod.__esModule) return mod;
        var result = {};
        if (mod != null) for (var k = ownKeys(mod), i = 0; i < k.length; i++) if (k[i] !== "default") __createBinding(result, mod, k[i]);
        __setModuleDefault(result, mod);
        return result;
    };
})();
Object.defineProperty(exports, "__esModule", { value: true });
exports.NovaChatPanel = void 0;
const vscode = __importStar(require("vscode"));
const api_1 = require("./api");
/**
 * Chat panel — messages go through the extension host so auth headers
 * are applied. LLM account tokens live on the Nova server.
 */
class NovaChatPanel {
    constructor(context) {
        this._disposables = [];
        this._context = context;
    }
    show() {
        if (this._panel) {
            this._panel.reveal(vscode.ViewColumn.Beside);
            return;
        }
        this._panel = vscode.window.createWebviewPanel(NovaChatPanel.viewType, 'Nova Arsenal', vscode.ViewColumn.Beside, {
            enableScripts: true,
            retainContextWhenHidden: true,
        });
        this._panel.webview.html = this._getHtml();
        this._panel.webview.onDidReceiveMessage(async (msg) => {
            if (!this._panel) {
                return;
            }
            if (msg?.type === 'chat' && typeof msg.message === 'string') {
                const reply = await (0, api_1.callNovaApi)('/api/chat/send', {
                    message: msg.message,
                    stream: false,
                });
                this._panel.webview.postMessage({
                    type: 'reply',
                    ok: Boolean(reply),
                    text: reply ||
                        'No response from Nova API. Is the server running? Use Nova: Sign In or Import sessions.',
                });
            }
            else if (msg?.type === 'status') {
                try {
                    const r = await fetch(`${(0, api_1.getApiBase)()}/api/health`);
                    this._panel.webview.postMessage({
                        type: 'status',
                        connected: r.ok,
                    });
                }
                catch {
                    this._panel.webview.postMessage({ type: 'status', connected: false });
                }
            }
            else if (msg?.type === 'signin') {
                await vscode.commands.executeCommand('nova-arsenal.signIn');
            }
            else if (msg?.type === 'import') {
                await vscode.commands.executeCommand('nova-arsenal.importAccounts');
            }
        }, undefined, this._disposables);
        this._panel.onDidDispose(() => this.dispose(), null, this._disposables);
    }
    dispose() {
        if (this._panel) {
            this._panel.dispose();
            this._panel = undefined;
        }
        while (this._disposables.length) {
            this._disposables.pop()?.dispose();
        }
    }
    _getHtml() {
        const apiUrl = (0, api_1.getApiBase)();
        return `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline';">
    <title>Nova Arsenal</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: var(--vscode-font-family, Consolas, monospace); background: #0d1117; color: #c9d1d9; height: 100vh; display: flex; flex-direction: column; }
        #header { background: #161b22; padding: 8px 16px; border-bottom: 1px solid #30363d; display: flex; align-items: center; gap: 12px; }
        #header h1 { font-size: 14px; color: #58a6ff; }
        #header .status { font-size: 11px; color: #8b949e; }
        #header .status.connected { color: #3fb950; }
        #chat { flex: 1; overflow-y: auto; padding: 16px; display: flex; flex-direction: column; gap: 8px; }
        .msg { padding: 8px 12px; border-radius: 6px; max-width: 90%; font-size: 13px; line-height: 1.4; white-space: pre-wrap; }
        .user { background: #1f6feb; color: #fff; align-self: flex-end; }
        .nova { background: #21262d; color: #c9d1d9; border: 1px solid #30363d; align-self: flex-start; }
        .nova.error { border-color: #f85149; color: #f85149; }
        #input-bar { display: flex; gap: 8px; padding: 8px 16px; background: #161b22; border-top: 1px solid #30363d; }
        #input { flex: 1; background: #0d1117; border: 1px solid #30363d; border-radius: 6px; padding: 8px 12px; color: #c9d1d9; font-family: inherit; font-size: 13px; outline: none; }
        #input:focus { border-color: #58a6ff; }
        #send { background: #238636; color: #fff; border: none; border-radius: 6px; padding: 8px 16px; cursor: pointer; font-size: 13px; }
        #send:hover { background: #2ea043; }
        #send:disabled { opacity: 0.5; cursor: default; }
        .quick-actions { display: flex; gap: 6px; padding: 8px 16px; background: #161b22; border-top: 1px solid #30363d; flex-wrap: wrap; }
        .qa-btn { background: #21262d; border: 1px solid #30363d; border-radius: 4px; padding: 4px 10px; color: #c9d1d9; font-size: 11px; cursor: pointer; }
        .qa-btn:hover { border-color: #58a6ff; color: #58a6ff; }
        .typing { color: #8b949e; font-style: italic; font-size: 12px; padding: 4px 12px; }
        .hint { font-size: 11px; color: #8b949e; padding: 0 16px 8px; }
        code { color: #79c0ff; }
    </style>
</head>
<body>
    <div id="header">
        <h1>Nova Arsenal</h1>
        <span class="status" id="status">connecting...</span>
        <span style="flex:1"></span>
        <button class="qa-btn" onclick="vscode.postMessage({type:'signin'})">Sign in</button>
        <button class="qa-btn" onclick="vscode.postMessage({type:'import'})">Import sessions</button>
    </div>
    <div class="hint">API: <code>${apiUrl}</code> · Claude Code / Codex sessions via Sign in or Import</div>
    <div id="chat"></div>
    <div class="quick-actions">
        <button class="qa-btn" onclick="quickAction('nmap scan')">Nmap</button>
        <button class="qa-btn" onclick="quickAction('payload gen')">Payload</button>
        <button class="qa-btn" onclick="quickAction('osint')">OSINT</button>
        <button class="qa-btn" onclick="quickAction('ctf solve')">CTF</button>
        <button class="qa-btn" onclick="quickAction('swarm scan')">Swarm</button>
        <button class="qa-btn" onclick="quickAction('zeroday hunt')">Zero-day</button>
    </div>
    <div id="input-bar">
        <input type="text" id="input" placeholder="Ask Nova…" onkeydown="if(event.key==='Enter') send()" />
        <button id="send" onclick="send()">Send</button>
    </div>
    <script>
        const vscode = acquireVsCodeApi();
        const chat = document.getElementById('chat');
        const input = document.getElementById('input');
        const sendBtn = document.getElementById('send');
        const status = document.getElementById('status');

        function setStatus(ok) {
            status.textContent = ok ? 'connected' : 'offline';
            status.className = 'status' + (ok ? ' connected' : '');
        }
        function checkStatus() { vscode.postMessage({ type: 'status' }); }
        setInterval(checkStatus, 10000);
        checkStatus();

        window.addEventListener('message', (event) => {
            const msg = event.data || {};
            if (msg.type === 'status') setStatus(!!msg.connected);
            if (msg.type === 'reply') {
                const typing = document.querySelector('.typing');
                if (typing) typing.remove();
                addMsg(msg.text || '', msg.ok ? 'nova' : 'nova error');
                sendBtn.disabled = false;
            }
        });

        function addMsg(text, cls) {
            const div = document.createElement('div');
            div.className = 'msg ' + cls;
            div.textContent = text;
            chat.appendChild(div);
            chat.scrollTop = chat.scrollHeight;
            return div;
        }

        function send() {
            const msg = input.value.trim();
            if (!msg) return;
            input.value = '';
            addMsg(msg, 'user');
            sendBtn.disabled = true;
            addMsg('…', 'typing');
            vscode.postMessage({ type: 'chat', message: msg });
        }

        function quickAction(action) {
            input.value = action;
            send();
        }
    </script>
</body>
</html>`;
    }
}
exports.NovaChatPanel = NovaChatPanel;
NovaChatPanel.viewType = 'novaArsenal.chat';
//# sourceMappingURL=panel.js.map