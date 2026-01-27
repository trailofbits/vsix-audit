import * as vscode from 'vscode';
const fetch = require('node-fetch');

export default function() {
    vscode.window.showInformationMessage(`API Consumer Function called...`);
}