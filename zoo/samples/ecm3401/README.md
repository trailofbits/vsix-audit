## Developed Extensions

`Extension-Attack-Suite` contains the attack suite, which hosts several different malicious attacks to perform on a user's device. It also exposes the honest API utilized in the Example & Malicious API extensions.

`Example-API-Extension` contains an extension that consumes the exposed honest API.

`Malicious-API-Extension` contains an extension that exposes a malicious version of the honest API and modifies the consumer to use it.

`Local-Web-Server` is a simple local web server assisting in the demonstration of how an attacker might exfiltrate confidential data.

## Performing the attacks

### Installing & Running extensions

1. Install `vsce` by running `npm install -g vsce`
2. Run `vsce package` in an extension's top-level directory to produce the `.vsix` file.
3. Run `code --install-extension myextension.vsix` to install an extension from a `.vsix` file. Replace `myextension.vsix` with the appropriate filename.

`NOTE: .vsix files have already been created for the submitted extensions so could directly install on VS Code `

4. Alternatively, run an extension directly in the Extension Development Host by pressing `F5` when editing an extension's source.

### Run specific attacks

**API spoofing attack**
1. Package and install `Extension-Attack-Suite` and `Example-API-Extension`.
2. Press `F5` from any extension directory.
3. Go to Command Palette and run the `ECM3401: API Consumer` command.
4. Verify Debug Console contains `81` in the output.
5. Package and install `Malicious-API-Extension`.
6. Repeat steps 2-4.
7. Verify Debug Console now contains `96` in the output.

**Docker attack**

1. Install the `ms-azuretools.vscode-docker` extension from the offical VSCode Markeplace.
2. Install or run  `Extension-Attack-Suite`.
3. Go to Command Palette and run `ECM3401: Tamper Docker extension`.

**Exfiltrate private SSH key & MAC Address**

1. `cd Local-Web-Server`
2. `npm install`
3. Run `node app.js` to start the local web server on port 3000.
4. Install or run  `Extension-Attack-Suite`
5. Go to Command Palette and either run the `ECM3401: Exfiltrate this device's SSH private key` or `ECM3401: Exfiltrate this device's MAC address` .
6. Check the terminal output for the POST request object containing the private SSH key or MAC address respectively.

**All other attacks (found in the Attack Suite)** 

Install or run  `Extension-Attack-Suite` and run commands from the Command Palette. All commands are prefixed with `ECM3401`.