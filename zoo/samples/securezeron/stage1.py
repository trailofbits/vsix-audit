import subprocess
import sys
import json

def generate_extension(config_file):
    # Load configuration from config.json for extension metadata
    with open(config_file, 'r') as f:
        config = json.load(f)

    # Construct the command to generate the extension
    command = [
        'yo',
        'code',
        '--extensionType=js',
        f'--extensionDisplayName={config["extensionDisplayName"]}',
        f'--extensionId={config["extensionId"]}',
        f'--extensionDescription={config["extensionDescription"]}',
        '--pkgManager=npm',
        '--gitInit=False'
    ]
    
    process = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
    try:
        process.communicate(input='y\n')  # Send 'y' to accept the prompt for JavaScript type checking
    except KeyboardInterrupt:
        process.terminate()
        sys.exit(1)

if __name__ == "__main__":
    config_file = 'config.json'
    generate_extension(config_file)
