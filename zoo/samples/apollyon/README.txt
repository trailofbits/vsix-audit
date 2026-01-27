Malicious VSCode extension POC

This is a proof-of-concept to show that how a vscode extension can be used as an attack vector.
It has the following functionality:
--> Exfiltrate all open files 
--> Change cryptocurrency(BTC,ETC) addresses in the users file to redirect funds

Try it out for yourself
--> Install VSCode, nodejs
--> Install npm packages code-generator and yo
--> Run the command `yo code` to generate an extension
--> Replace the generated package.json and extension.js files
--> Edit extension.js to include your own webhook
--> Run the extension preview 
