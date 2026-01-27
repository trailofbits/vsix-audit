import * as vscode from 'vscode';
const { spawn, exec } = require('child_process');
// const wincmd = require('node-windows'); // On Windows only!

export default function() {

    const path = "/Users/alexbabalitis/Desktop/test.sh";

    const exe = exec(path,[]);
    vscode.window.showInformationMessage("Executed malicious script");

    // On Windows, execute command as an administrator.
    // wincmd.elevate('.exe file');

    exe.stdout.on('data', (data: any) => {
        console.log(`Content in stdout: ${data}`);
    });
    
    exe.stderr.on('data', (data: any) => {
        console.error(`Content in stderr: ${data}`);
    });
      
    exe.on('close', (code: any) => {
        console.log(`Child process exited with code: ${code}`);
    });
}