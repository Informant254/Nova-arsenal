import * as vscode from 'vscode';
import {
    callNovaApi,
    callNovaApiGet,
    probeHealth,
    setOutputChannel,
    showOutput,
} from './api';
import { NovaChatPanel } from './panel';

let chatPanel: NovaChatPanel | undefined;
let output: vscode.OutputChannel;

export function activate(context: vscode.ExtensionContext) {
    output = vscode.window.createOutputChannel('Nova Arsenal');
    setOutputChannel(output);
    output.appendLine('[Nova] Activating Nova-Arsenal extension');

    context.subscriptions.push(
        vscode.commands.registerCommand('nova-arsenal.openChat', () => {
            if (!chatPanel) {
                chatPanel = new NovaChatPanel(context);
            }
            chatPanel.show();
        }),
        vscode.commands.registerCommand('nova-arsenal.signIn', () => signIn()),
        vscode.commands.registerCommand('nova-arsenal.importAccounts', () => importAccounts()),
        vscode.commands.registerCommand('nova-arsenal.showAccounts', () => showAccounts()),
        vscode.commands.registerCommand('nova-arsenal.configureApi', () => configureApi()),
        vscode.commands.registerCommand('nova-arsenal.quickScan', () => quickScan()),
        vscode.commands.registerCommand('nova-arsenal.runNmap', () => runNmap()),
        vscode.commands.registerCommand('nova-arsenal.runPayloadGen', () => runPayloadGen()),
        vscode.commands.registerCommand('nova-arsenal.runOsint', () => runOsint()),
        vscode.commands.registerCommand('nova-arsenal.ctfSolver', () => runCtf()),
        output
    );

    void probeHealth().then((ok) => {
        output.appendLine(ok ? '[Nova] API reachable' : '[Nova] API offline — start: python -m nova_arsenal.api');
    });
}

export function deactivate() {
    chatPanel?.dispose();
    chatPanel = undefined;
}

async function configureApi() {
    const current = vscode.workspace
        .getConfiguration('nova-arsenal')
        .get<string>('apiUrl', 'http://localhost:8000');
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
    const provider = await vscode.window.showQuickPick(
        [
            {
                label: 'openai-oauth',
                description: 'ChatGPT Plus/Pro via Codex OAuth (run on host CLI if remote)',
            },
            { label: 'ollama', description: 'Local Ollama (no cloud account / free offline)' },
            { label: 'anthropic', description: 'Claude (paste OAuth/session token from Claude Code)' },
            { label: 'openai', description: 'OpenAI / Codex (paste session or API token)' },
            { label: 'gemini', description: 'Google Gemini (API key or token)' },
            { label: 'openrouter', description: 'OpenRouter key' },
            { label: 'import', description: 'Import Claude Code / Codex sessions from this machine' },
        ],
        { placeHolder: 'Sign in with AI account or use local LLM' }
    );
    if (!provider) {
        return;
    }
    if (provider.label === 'import') {
        await importAccounts();
        return;
    }
    if (provider.label === 'openai-oauth') {
        vscode.window.showInformationMessage(
            'Run on the machine with a browser: nova-agent login --provider openai --oauth'
        );
        output.appendLine('[Nova] ChatGPT OAuth: nova-agent login --provider openai --oauth');
        output.appendLine('[Nova] Headless: nova-agent login --provider openai --oauth --device-code');
        output.show(true);
        return;
    }
    if (provider.label === 'ollama') {
        const model = await vscode.window.showInputBox({
            prompt: 'Ollama model (leave empty to auto-detect)',
            placeHolder: 'llama3.2',
        });
        const result = await callNovaApi('/api/llm/accounts/login', {
            provider: 'ollama',
            model: model || '',
            label: 'vscode:ollama',
        });
        if (result) {
            vscode.window.showInformationMessage('Nova: local Ollama registered');
            output.appendLine(result);
        }
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

    const result = await callNovaApi('/api/llm/accounts/login', {
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
    const result = await callNovaApi('/api/llm/accounts/import', {});
    if (result) {
        vscode.window.showInformationMessage('Nova: imported local AI sessions (see Output)');
        showOutput(result);
    }
}

async function showAccounts() {
    const status = await callNovaApiGet('/api/llm/status');
    if (status) {
        showOutput(status);
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
    await vscode.window.withProgress(
        {
            location: vscode.ProgressLocation.Notification,
            title: `Nova: Scanning ${target}...`,
        },
        async () => {
            const result = await callNovaApi('/api/chat/send', {
                message: `Quick scan ${target} for open ports and services`,
                stream: false,
            });
            if (result) {
                showOutput(result);
                vscode.window.showInformationMessage(`Nova scan complete for ${target}`);
            }
        }
    );
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
    const result = await callNovaApi('/api/chat/send', {
        message: `Run nmap scan against ${target}${ports ? ` on ports ${ports}` : ''}`,
        stream: false,
    });
    if (result) {
        showOutput(result);
    }
}

async function runPayloadGen() {
    const ptype = await vscode.window.showQuickPick(
        ['reverse_shell', 'bind_shell', 'webshell', 'download_exec'],
        { placeHolder: 'Select payload type' }
    );
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
    const result = await callNovaApi('/api/chat/send', {
        message: `Generate ${ptype} payload with LHOST=${lhost} LPORT=${lport}`,
        stream: false,
    });
    if (result) {
        showOutput(result);
    }
}

async function runOsint() {
    const domain = await vscode.window.showInputBox({ prompt: 'Target domain' });
    if (!domain) {
        return;
    }
    await vscode.window.withProgress(
        {
            location: vscode.ProgressLocation.Notification,
            title: `Nova: OSINT on ${domain}...`,
        },
        async () => {
            const result = await callNovaApi('/api/chat/send', {
                message: `Run OSINT chain investigation on ${domain}`,
                stream: false,
            });
            if (result) {
                showOutput(result);
            }
        }
    );
}

async function runCtf() {
    const name = await vscode.window.showInputBox({ prompt: 'Challenge name' });
    if (!name) {
        return;
    }
    const ctype = await vscode.window.showQuickPick(
        ['web', 'crypto', 'stego', 'forensics', 'reversing', 'pwn', 'osint', 'recon', 'misc'],
        { placeHolder: 'Challenge type' }
    );
    if (!ctype) {
        return;
    }
    const url = await vscode.window.showInputBox({ prompt: 'Challenge URL (optional)' });
    const result = await callNovaApi('/api/chat/send', {
        message: `Solve CTF challenge "${name}" of type ${ctype}${url ? ` at ${url}` : ''}`,
        stream: false,
    });
    if (result) {
        showOutput(result);
    }
}
