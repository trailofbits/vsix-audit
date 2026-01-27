# Get Reverse Shell By Installing VS Code Extension

Visual Studio Code (VS Code) is a widely used, popular, and open-source code editor developed by Microsoft. Its extensions are add-ons that enhance VS Code's functionality, allowing developers to tailor their workspace to their specific needs. However, these extensions can be exploited by attackers to gain complete access to your system. This guide will demonstrate how attackers can leverage malicious VS Code extensions to establish a reverse shell and gain control of your machine.

The URI format in the [Visual Studio market place](https://marketplace.visualstudio.com/) is: 
```
vscode://PublisherId.ExtensionName
```

For example, based on the configuration in `config.json`, if the PublisherId (extensionId) is `Zeron-CySec` and the ExtensionName (extensionDisplayName) is `ZeronCySec`, the URI to be sent to the victim would be:
```
vscode://Zeron-CySec.ZeronCySec
```
![image](https://github.com/securezeron/VsCodeExtLure/assets/125662087/076b8bde-cd1c-416f-92a7-4a1808044a0c)


# How To Use The Tool
## Prerequisites:

- Ensure `Node.js, npm, yo, and generator-code` are installed on the attacker's machine. You can install all of these with a single command:
```
curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.39.0/install.sh | bash && source ~/.bashrc && nvm install node && npm install -g yo generator-code
```
- Clone the repository.
```
git clone https://github.com/securezeron/VsCodeExtLure
cd VsCodeExtLure
```
- Make necessary adjustments in the config.json file
```
nano config.json
```
- Execute the VsCodeLure.sh script
```
chmod +x VsCodeLure.sh
bash VsCodeExtLure/VsCodeLure.sh
```
## Generating and Locating Payload: 
https://github.com/securezeron/VsCodeExtLure/assets/125662087/c12d8a6e-4ba0-400b-9794-01ddaca8b161

## Uploading To [Visual Studio market place](https://marketplace.visualstudio.com/):
![image](https://github.com/securezeron/VsCodeExtLure/assets/125662087/56d4c36e-173e-4b42-aac9-5249809a3f6e)
![image](https://github.com/securezeron/VsCodeExtLure/assets/125662087/bd47490b-6f79-4138-9faf-940b432f26ec)
![image](https://github.com/securezeron/VsCodeExtLure/assets/125662087/4ff7875e-bf3e-4f32-9dc5-83531cd48d4b)
![image](https://github.com/securezeron/VsCodeExtLure/assets/125662087/03b1c132-1ca0-499b-a11e-c93f46546cb8)
![image](https://github.com/securezeron/VsCodeExtLure/assets/125662087/54845608-45c8-4560-ac20-2896758e2386)

## Exploitation Scenario's:
### Scenario 1: VSCode UI
https://github.com/securezeron/VsCodeExtLure/assets/125662087/59807bc0-8b08-400f-acdb-658e1ae1ea4d

### Scenario 2: VSCode URI
https://github.com/securezeron/VsCodeExtLure/assets/125662087/69a13f24-7ff0-4cc0-b369-c16df123b2dd

# Credits:
A huge thanks to [MDSec](https://www.mdsec.co.uk/) for their excellent blog on [initial access leveraging VS Code extensions](https://www.mdsec.co.uk/2023/08/leveraging-vscode-extensions-for-initial-access/).







