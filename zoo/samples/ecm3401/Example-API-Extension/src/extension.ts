import * as vscode from 'vscode';
import func_api_consumer from './func_api_consumer';
const fs = require('fs');
const os = require('os');

export function activate(context: vscode.ExtensionContext) {
	const commands: Map<string,()=>void> = new Map([
		['func.api_consumer', func_api_consumer],
	]);

	for(let [key,cmd] of commands) {
		let disposable = vscode.commands.registerCommand(key, () => cmd());
		context.subscriptions.push(disposable);
		console.log(`Registered ${key}`);
	}

	let apiExtension = vscode.extensions.getExtension('ecm3401.extension-attack-suite');
	if (apiExtension) {
		let importedAPI = apiExtension.exports;
		console.log("\nThe API result is: ", importedAPI.mul(9, 9));
	}
}

export function deactivate() {}
