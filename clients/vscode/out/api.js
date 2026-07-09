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
exports.setOutputChannel = setOutputChannel;
exports.getApiBase = getApiBase;
exports.probeHealth = probeHealth;
exports.callNovaApi = callNovaApi;
exports.callNovaApiGet = callNovaApiGet;
exports.showOutput = showOutput;
const vscode = __importStar(require("vscode"));
let output;
function setOutputChannel(ch) {
    output = ch;
}
function getApiBase() {
    return vscode.workspace
        .getConfiguration('nova-arsenal')
        .get('apiUrl', 'http://localhost:8000');
}
function authHeaders() {
    const apiKey = vscode.workspace.getConfiguration('nova-arsenal').get('apiKey', '');
    const headers = { 'Content-Type': 'application/json' };
    if (apiKey) {
        if (apiKey.startsWith('na_')) {
            headers['X-API-Key'] = apiKey;
        }
        else {
            headers['Authorization'] = `Bearer ${apiKey}`;
        }
    }
    return headers;
}
async function probeHealth() {
    try {
        const response = await fetch(`${getApiBase()}/api/health`);
        return response.ok;
    }
    catch {
        return false;
    }
}
async function callNovaApi(path, body) {
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
        const data = (await response.json());
        return (data.reply ||
            data.response ||
            data.message ||
            JSON.stringify(data, null, 2));
    }
    catch (err) {
        const msg = err instanceof Error ? err.message : String(err);
        vscode.window.showErrorMessage(`Nova API connection failed: ${msg}`);
        output?.appendLine(`[Nova] Connection failed: ${msg}`);
        return null;
    }
}
async function callNovaApiGet(path) {
    try {
        const response = await fetch(`${getApiBase()}${path}`, { headers: authHeaders() });
        if (!response.ok) {
            vscode.window.showErrorMessage(`Nova API error: ${response.status}`);
            return null;
        }
        const data = await response.json();
        return JSON.stringify(data, null, 2);
    }
    catch (err) {
        const msg = err instanceof Error ? err.message : String(err);
        vscode.window.showErrorMessage(`Nova API connection failed: ${msg}`);
        return null;
    }
}
function showOutput(text) {
    if (!output) {
        output = vscode.window.createOutputChannel('Nova Arsenal');
    }
    output.clear();
    output.appendLine(text);
    output.show(true);
}
//# sourceMappingURL=api.js.map