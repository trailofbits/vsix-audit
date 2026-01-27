import * as vscode from 'vscode';
const fetch = require('node-fetch');

export default function() {
    fetch('https://www.google.gr').then((res:any)=>res.text()).then((text:string)=> {

        vscode.window.showInformationMessage(`Extracted ${text}`);
    }).catch((e:Error) => {
        console.error(e);
    });
}