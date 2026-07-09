import * as vscode from 'vscode';

let output: vscode.OutputChannel | undefined;

export function setOutputChannel(ch: vscode.OutputChannel) {
    output = ch;
}

export function getApiBase(): string {
    return vscode.workspace
        .getConfiguration('nova-arsenal')
        .get<string>('apiUrl', 'http://localhost:8000');
}

function authHeaders(): Record<string, string> {
    const apiKey = vscode.workspace.getConfiguration('nova-arsenal').get<string>('apiKey', '');
    const headers: Record<string, string> = { 'Content-Type': 'application/json' };
    if (apiKey) {
        if (apiKey.startsWith('na_')) {
            headers['X-API-Key'] = apiKey;
        } else {
            headers['Authorization'] = `Bearer ${apiKey}`;
        }
    }
    return headers;
}

export async function probeHealth(): Promise<boolean> {
    try {
        const response = await fetch(`${getApiBase()}/api/health`);
        return response.ok;
    } catch {
        return false;
    }
}

export async function callNovaApi(path: string, body: unknown): Promise<string | null> {
    try {
        const url = `${getApiBase()}${path}`;
        const response = await fetch(url, {
            method: 'POST',
            headers: authHeaders(),
            body: JSON.stringify(body),
        });
        if (!response.ok) {
            const text = await response.text();
            vscode.window.showErrorMessage(`Nova API error: ${response.status} ${response.statusText}`);
            output?.appendLine(`[Nova] API error ${response.status}: ${text.slice(0, 500)}`);
            return null;
        }
        const data = (await response.json()) as Record<string, unknown>;
        return (
            (data.reply as string) ||
            (data.response as string) ||
            (data.message as string) ||
            JSON.stringify(data, null, 2)
        );
    } catch (err: unknown) {
        const msg = err instanceof Error ? err.message : String(err);
        vscode.window.showErrorMessage(`Nova API connection failed: ${msg}`);
        output?.appendLine(`[Nova] Connection failed: ${msg}`);
        return null;
    }
}

export async function callNovaApiGet(path: string): Promise<string | null> {
    try {
        const response = await fetch(`${getApiBase()}${path}`, { headers: authHeaders() });
        if (!response.ok) {
            vscode.window.showErrorMessage(`Nova API error: ${response.status}`);
            return null;
        }
        const data = await response.json();
        return JSON.stringify(data, null, 2);
    } catch (err: unknown) {
        const msg = err instanceof Error ? err.message : String(err);
        vscode.window.showErrorMessage(`Nova API connection failed: ${msg}`);
        return null;
    }
}

export function showOutput(text: string) {
    if (!output) {
        output = vscode.window.createOutputChannel('Nova Arsenal');
    }
    output.clear();
    output.appendLine(text);
    output.show(true);
}
