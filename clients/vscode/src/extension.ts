import * as vscode from 'vscode';
import { NovaChatPanel } from './panel';

let chatPanel: NovaChatPanel | undefined;

export function activate(context: vscode.ExtensionContext) {
    console.log('[Nova] Activating Nova-Arsenal extension');

    const openChatCmd = vscode.commands.registerCommand('nova-arsenal.openChat', () => {
        if (!chatPanel) {
            chatPanel = new NovaChatPanel(context);
        }
        chatPanel.show();
    });

    const quickScanCmd = vscode.commands.registerCommand('nova-arsenal.quickScan', async () => {
        const target = await vscode.window.showInputBox({
            prompt: 'Target IP or hostname',
            placeHolder: 'e.g. scanme.nmap.org',
            value: vscode.workspace.getConfiguration('nova-arsenal').get('defaultTarget', ''),
        });
        if (!target) return;

        vscode.window.withProgress({
            location: vscode.ProgressLocation.Notification,
            title: `Nova: Scanning ${target}...`,
            cancellable: true,
        }, async (progress, token) => {
            progress.report({ message: 'Running reconnaissance...' });
            const result = await callNovaApi('/api/chat', {
                message: `Quick scan ${target} for open ports and services`,
            });
            if (result) {
                vscode.window.showInformationMessage(`Nova scan complete for ${target}`);
            }
        });
    });

    const nmapCmd = vscode.commands.registerCommand('nova-arsenal.runNmap', async () => {
        const target = await vscode.window.showInputBox({ prompt: 'Target' });
        if (!target) return;
        const ports = await vscode.window.showInputBox({
            prompt: 'Ports (optional)',
            placeHolder: 'e.g. 80,443 or 1-1000',
        });

        const result = await callNovaApi('/api/chat', {
            message: `Run nmap scan against ${target}${ports ? ` on ports ${ports}` : ''}`,
        });
        if (result) {
            showOutput(result);
        }
    });

    const payloadCmd = vscode.commands.registerCommand('nova-arsenal.runPayloadGen', async () => {
        const ptype = await vscode.window.showQuickPick(
            ['reverse_shell', 'bind_shell', 'webshell', 'download_exec'],
            { placeHolder: 'Select payload type' }
        );
        if (!ptype) return;
        const lhost = await vscode.window.showInputBox({ prompt: 'LHOST (listener IP)' });
        if (!lhost) return;
        const lport = await vscode.window.showInputBox({ prompt: 'LPORT (listener port)' });
        if (!lport) return;

        const result = await callNovaApi('/api/chat', {
            message: `Generate ${ptype} payload with LHOST=${lhost} LPORT=${lport}`,
        });
        if (result) {
            showOutput(result);
        }
    });

    const osintCmd = vscode.commands.registerCommand('nova-arsenal.runOsint', async () => {
        const domain = await vscode.window.showInputBox({ prompt: 'Target domain' });
        if (!domain) return;

        vscode.window.withProgress({
            location: vscode.ProgressLocation.Notification,
            title: `Nova: OSINT investigation on ${domain}...`,
        }, async () => {
            const result = await callNovaApi('/api/chat', {
                message: `Run OSINT chain investigation on ${domain}`,
            });
            if (result) {
                showOutput(result);
            }
        });
    });

    const ctfCmd = vscode.commands.registerCommand('nova-arsenal.ctfSolver', async () => {
        const name = await vscode.window.showInputBox({ prompt: 'Challenge name' });
        if (!name) return;
        const ctype = await vscode.window.showQuickPick(
            ['web', 'crypto', 'stego', 'forensics', 'reversing', 'pwn', 'osint', 'recon', 'misc'],
            { placeHolder: 'Challenge type' }
        );
        if (!ctype) return;
        const url = await vscode.window.showInputBox({ prompt: 'Challenge URL (optional)' });

        const result = await callNovaApi('/api/chat', {
            message: `Solve CTF challenge "${name}" of type ${ctype}${url ? ` at ${url}` : ''}`,
        });
        if (result) {
            showOutput(result);
        }
    });

    context.subscriptions.push(
        openChatCmd, quickScanCmd, nmapCmd, payloadCmd, osintCmd, ctfCmd
    );
}

export function deactivate() {
    if (chatPanel) {
        chatPanel.dispose();
    }
}

async function callNovaApi(path: string, body: any): Promise<string | null> {
    const config = vscode.workspace.getConfiguration('nova-arsenal');
    const apiUrl = config.get<string>('apiUrl', 'http://localhost:8000');
    const apiKey = config.get<string>('apiKey', '');

    try {
        const url = `${apiUrl}${path}`;
        const headers: Record<string, string> = { 'Content-Type': 'application/json' };
        if (apiKey) {
            headers['Authorization'] = `Bearer ${apiKey}`;
        }

        const response = await fetch(url, {
            method: 'POST',
            headers,
            body: JSON.stringify(body),
        });

        if (!response.ok) {
            vscode.window.showErrorMessage(`Nova API error: ${response.status} ${response.statusText}`);
            return null;
        }

        const data = await response.json();
        return data.response || data.message || JSON.stringify(data);
    } catch (err: any) {
        vscode.window.showErrorMessage(`Nova API connection failed: ${err.message}`);
        return null;
    }
}

function showOutput(text: string) {
    const panel = vscode.window.createOutputPanel('nova-arsenal');
    panel.append(text);
    panel.show();
}
