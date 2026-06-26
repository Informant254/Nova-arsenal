import * as vscode from 'vscode';

export class NovaChatPanel {
    public static readonly viewType = 'novaArsenal.chat';

    private _panel: vscode.WebviewPanel | undefined;
    private _context: vscode.ExtensionContext;

    constructor(context: vscode.ExtensionContext) {
        this._context = context;
    }

    public show() {
        if (this._panel) {
            this._panel.reveal(vscode.ViewColumn.Beside);
            return;
        }

        this._panel = vscode.window.createWebviewPanel(
            NovaChatPanel.viewType,
            'Nova Arsenal',
            vscode.ViewColumn.Beside,
            {
                enableScripts: true,
                retainContextWhenHidden: true,
            }
        );

        this._panel.webview.html = this._getHtml();
        this._panel.onDidDispose(() => { this._panel = undefined; });
    }

    public dispose() {
        if (this._panel) {
            this._panel.dispose();
            this._panel = undefined;
        }
    }

    private _getHtml(): string {
        const apiUrl = vscode.workspace.getConfiguration('nova-arsenal').get('apiUrl', 'http://localhost:8000');

        return `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Nova Arsenal</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: 'Consolas', 'Monaco', monospace; background: #0d1117; color: #c9d1d9; height: 100vh; display: flex; flex-direction: column; }
        #header { background: #161b22; padding: 8px 16px; border-bottom: 1px solid #30363d; display: flex; align-items: center; gap: 12px; }
        #header h1 { font-size: 14px; color: #58a6ff; }
        #header .status { font-size: 11px; color: #8b949e; }
        #header .status.connected { color: #3fb950; }
        #chat { flex: 1; overflow-y: auto; padding: 16px; display: flex; flex-direction: column; gap: 8px; }
        .msg { padding: 8px 12px; border-radius: 6px; max-width: 85%; font-size: 13px; line-height: 1.4; white-space: pre-wrap; }
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
    </style>
</head>
<body>
    <div id="header">
        <h1>Nova Arsenal</h1>
        <span class="status" id="status">connecting...</span>
    </div>
    <div id="chat"></div>
    <div class="quick-actions">
        <button class="qa-btn" onclick="quickAction('nmap scan')">Nmap</button>
        <button class="qa-btn" onclick="quickAction('payload gen')">Payload</button>
        <button class="qa-btn" onclick="quickAction('osint')">OSINT</button>
        <button class="qa-btn" onclick="quickAction('ctf solve')">CTF</button>
        <button class="qa-btn" onclick="quickAction('swarm scan')">Swarm</button>
        <button class="qa-btn" onclick="quickAction('compliance')">Compliance</button>
    </div>
    <div id="input-bar">
        <input type="text" id="input" placeholder="Ask Nova to do something..." onkeydown="if(event.key==='Enter') send()" />
        <button id="send" onclick="send()">Send</button>
    </div>
    <script>
        const apiUrl = '${apiUrl}';
        const chat = document.getElementById('chat');
        const input = document.getElementById('input');
        const sendBtn = document.getElementById('send');
        const status = document.getElementById('status');

        async function checkStatus() {
            try {
                const r = await fetch(apiUrl + '/api/health');
                if (r.ok) { status.textContent = 'connected'; status.className = 'status connected'; }
                else { status.textContent = 'error'; status.className = 'status'; }
            } catch { status.textContent = 'offline'; status.className = 'status'; }
        }
        setInterval(checkStatus, 10000);
        checkStatus();

        function addMsg(text, cls) {
            const div = document.createElement('div');
            div.className = 'msg ' + cls;
            div.textContent = text;
            chat.appendChild(div);
            chat.scrollTop = chat.scrollHeight;
            return div;
        }

        async function send() {
            const msg = input.value.trim();
            if (!msg) return;
            input.value = '';
            addMsg(msg, 'user');
            sendBtn.disabled = true;
            const typing = addMsg('...', 'typing');

            try {
                const resp = await fetch(apiUrl + '/api/chat', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ message: msg }),
                });
                const data = await resp.json();
                typing.remove();
                addMsg(data.response || data.message || JSON.stringify(data), 'nova');
            } catch (err) {
                typing.remove();
                addMsg('Connection error: ' + err.message, 'nova error');
            }
            sendBtn.disabled = false;
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
