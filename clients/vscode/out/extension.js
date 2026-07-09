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
exports.activate = activate;
exports.deactivate = deactivate;
const vscode = __importStar(require("vscode"));
const api_1 = require("./api");
const panel_1 = require("./panel");
let chatPanel;
let output;
function activate(context) {
    output = vscode.window.createOutputChannel('Nova Arsenal');
    (0, api_1.setOutputChannel)(output);
    output.appendLine('[Nova] Activating Nova-Arsenal extension');
    context.subscriptions.push(vscode.commands.registerCommand('nova-arsenal.openChat', () => {
        if (!chatPanel) {
            chatPanel = new panel_1.NovaChatPanel(context);
        }
        chatPanel.show();
    }), vscode.commands.registerCommand('nova-arsenal.signIn', () => signIn()), vscode.commands.registerCommand('nova-arsenal.importAccounts', () => importAccounts()), vscode.commands.registerCommand('nova-arsenal.showAccounts', () => showAccounts()), vscode.commands.registerCommand('nova-arsenal.configureApi', () => configureApi()), vscode.commands.registerCommand('nova-arsenal.quickScan', () => quickScan()), vscode.commands.registerCommand('nova-arsenal.runNmap', () => runNmap()), vscode.commands.registerCommand('nova-arsenal.runPayloadGen', () => runPayloadGen()), vscode.commands.registerCommand('nova-arsenal.runOsint', () => runOsint()), vscode.commands.registerCommand('nova-arsenal.ctfSolver', () => runCtf()), output);
    void (0, api_1.probeHealth)().then((ok) => {
        output.appendLine(ok ? '[Nova] API reachable' : '[Nova] API offline — start: python -m nova_arsenal.api');
    });
}
function deactivate() {
    chatPanel?.dispose();
    chatPanel = undefined;
}
async function configureApi() {
    const current = vscode.workspace
        .getConfiguration('nova-arsenal')
        .get('apiUrl', 'http://localhost:8000');
    const url = await vscode.window.showInputBox({ prompt: 'Nova API URL', value: current });
    if (!url) {
        return;
    }
    await vscode.workspace
        .getConfiguration('nova-arsenal')
        .update('apiUrl', url, vscode.ConfigurationTarget.Global);
    vscode.window.showInformationMessage(`Nova API URL set to ${url}`);
}
async function signIn() {
    const provider = await vscode.window.showQuickPick([
        { label: 'anthropic', description: 'Claude (paste OAuth/session token from Claude Code)' },
        { label: 'openai', description: 'OpenAI / Codex (paste session or API token)' },
        { label: 'gemini', description: 'Google Gemini (API key or token)' },
        { label: 'openrouter', description: 'OpenRouter key' },
        { label: 'import', description: 'Import Claude Code / Codex sessions from this machine' },
    ], { placeHolder: 'Sign in with AI account (Codex / Claude Code style)' });
    if (!provider) {
        return;
    }
    if (provider.label === 'import') {
        await importAccounts();
        return;
    }
    const token = await vscode.window.showInputBox({
        prompt: `Paste ${provider.label} session token or API key`,
        password: true,
        ignoreFocusOut: true,
    });
    if (!token) {
        return;
    }
    const result = await (0, api_1.callNovaApi)('/api/llm/accounts/login', {
        provider: provider.label,
        token,
        label: `vscode:${provider.label}`,
    });
    if (result) {
        vscode.window.showInformationMessage(`Nova: signed in to ${provider.label}`);
        output.appendLine(`[Nova] Signed in: ${provider.label}`);
    }
}
async function importAccounts() {
    const result = await (0, api_1.callNovaApi)('/api/llm/accounts/import', {});
    if (result) {
        vscode.window.showInformationMessage('Nova: imported local AI sessions (see Output)');
        (0, api_1.showOutput)(result);
    }
}
async function showAccounts() {
    const status = await (0, api_1.callNovaApiGet)('/api/llm/status');
    if (status) {
        (0, api_1.showOutput)(status);
        vscode.window.showInformationMessage('Nova LLM status → Output: Nova Arsenal');
    }
}
async function quickScan() {
    const target = await vscode.window.showInputBox({
        prompt: 'Target IP or hostname',
        placeHolder: 'e.g. scanme.nmap.org',
        value: vscode.workspace.getConfiguration('nova-arsenal').get('defaultTarget', ''),
    });
    if (!target) {
        return;
    }
    await vscode.window.withProgress({
        location: vscode.ProgressLocation.Notification,
        title: `Nova: Scanning ${target}...`,
    }, async () => {
        const result = await (0, api_1.callNovaApi)('/api/chat/send', {
            message: `Quick scan ${target} for open ports and services`,
            stream: false,
        });
        if (result) {
            (0, api_1.showOutput)(result);
            vscode.window.showInformationMessage(`Nova scan complete for ${target}`);
        }
    });
}
async function runNmap() {
    const target = await vscode.window.showInputBox({ prompt: 'Target' });
    if (!target) {
        return;
    }
    const ports = await vscode.window.showInputBox({
        prompt: 'Ports (optional)',
        placeHolder: 'e.g. 80,443 or 1-1000',
    });
    const result = await (0, api_1.callNovaApi)('/api/chat/send', {
        message: `Run nmap scan against ${target}${ports ? ` on ports ${ports}` : ''}`,
        stream: false,
    });
    if (result) {
        (0, api_1.showOutput)(result);
    }
}
async function runPayloadGen() {
    const ptype = await vscode.window.showQuickPick(['reverse_shell', 'bind_shell', 'webshell', 'download_exec'], { placeHolder: 'Select payload type' });
    if (!ptype) {
        return;
    }
    const lhost = await vscode.window.showInputBox({ prompt: 'LHOST (listener IP)' });
    if (!lhost) {
        return;
    }
    const lport = await vscode.window.showInputBox({ prompt: 'LPORT (listener port)' });
    if (!lport) {
        return;
    }
    const result = await (0, api_1.callNovaApi)('/api/chat/send', {
        message: `Generate ${ptype} payload with LHOST=${lhost} LPORT=${lport}`,
        stream: false,
    });
    if (result) {
        (0, api_1.showOutput)(result);
    }
}
async function runOsint() {
    const domain = await vscode.window.showInputBox({ prompt: 'Target domain' });
    if (!domain) {
        return;
    }
    await vscode.window.withProgress({
        location: vscode.ProgressLocation.Notification,
        title: `Nova: OSINT on ${domain}...`,
    }, async () => {
        const result = await (0, api_1.callNovaApi)('/api/chat/send', {
            message: `Run OSINT chain investigation on ${domain}`,
            stream: false,
        });
        if (result) {
            (0, api_1.showOutput)(result);
        }
    });
}
async function runCtf() {
    const name = await vscode.window.showInputBox({ prompt: 'Challenge name' });
    if (!name) {
        return;
    }
    const ctype = await vscode.window.showQuickPick(['web', 'crypto', 'stego', 'forensics', 'reversing', 'pwn', 'osint', 'recon', 'misc'], { placeHolder: 'Challenge type' });
    if (!ctype) {
        return;
    }
    const url = await vscode.window.showInputBox({ prompt: 'Challenge URL (optional)' });
    const result = await (0, api_1.callNovaApi)('/api/chat/send', {
        message: `Solve CTF challenge "${name}" of type ${ctype}${url ? ` at ${url}` : ''}`,
        stream: false,
    });
    if (result) {
        (0, api_1.showOutput)(result);
    }
}
//# sourceMappingURL=extension.js.map