/*
    GlassWorm Credential Harvesting Detection
    Detects patterns for harvesting NPM, GitHub, OpenVSX, Git, and SSH credentials
    Based on GlassWorm credential theft for self-propagation
*/

rule GlassWorm_NPM_Credential_Harvesting {
    meta:
        description = "Detects NPM credential harvesting patterns"
        severity = "high"
        score = "85"
        author = "Kirin Scanner (by Knostic)  - GlassWorm Detection Suite"
        date = "2025-10-18"
        reference = "https://www.koi.ai/blog/glassworm-first-self-propagating-worm-using-invisible-code-hits-openvsx-marketplace"
    
    strings:
        // NPM credential file paths
        $npmrc = ".npmrc" ascii wide
        $npm_token = "NPM_TOKEN" ascii wide
        $npm_auth = "npm_auth" ascii wide
        $npm_config = "npm_config" ascii wide
        
        // NPM authentication patterns
        $npm_login = "npm login" ascii wide
        $npm_publish = "npm publish" ascii wide
        $npm_whoami = "npm whoami" ascii wide
        $npm_auth_token = "authToken" ascii wide
        
        // File system access for credentials
        $read_file = "readFile" ascii wide
        $read_file_sync = "readFileSync" ascii wide
        $fs_read = "fs.read" ascii wide
        $path_join = "path.join" ascii wide
        $os_homedir = "os.homedir" ascii wide
        
        // Environment variable access
        $process_env = "process.env" ascii wide
        $env_npm = "NPM_" ascii wide
        
        // Credential exfiltration
        $http_post = "POST" ascii wide
        $https_post = "https" ascii wide
        $fetch_post = "fetch(" ascii wide
        
    condition:
        // High confidence: NPM credential access + file reading + network exfiltration
        (any of ($npmrc, $npm_token, $npm_auth, $npm_config, $npm_auth_token)) and
        (any of ($read_file, $read_file_sync, $fs_read, $path_join, $os_homedir, $process_env)) and
        (any of ($http_post, $https_post, $fetch_post, $npm_login, $npm_publish, $npm_whoami, $env_npm))
}

rule GlassWorm_GitHub_Credential_Harvesting {
    meta:
        description = "Detects GitHub credential harvesting patterns"
        severity = "high"
        score = "85"
        author = "Kirin Scanner (by Knostic)  - GlassWorm Detection Suite"
        date = "2025-10-18"
    
    strings:
        // GitHub credential file paths
        $gitconfig = ".gitconfig" ascii wide
        $github_token = "GITHUB_TOKEN" ascii wide
        $gh_token = "GH_TOKEN" ascii wide
        $github_auth = "github_auth" ascii wide
        
        // GitHub API access
        $github_api = "api.github.com" ascii wide
        $github_token_auth = "token" ascii wide
        $github_bearer = "Bearer" ascii wide
        $github_auth_header = "Authorization" ascii wide
        
        // Git credential access
        $git_credentials = ".git-credentials" ascii wide
        $git_config = "git config" ascii wide
        $git_remote = "git remote" ascii wide
        $git_url = "git@github.com" ascii wide
        
        // SSH key access
        $ssh_dir = ".ssh" ascii wide
        $id_rsa = "id_rsa" ascii wide
        $id_ed25519 = "id_ed25519" ascii wide
        $ssh_key = "ssh_key" ascii wide
        
        // File system access
        $read_file = "readFile" ascii wide
        $read_file_sync = "readFileSync" ascii wide
        $fs_read = "fs.read" ascii wide
        $path_join = "path.join" ascii wide
        $os_homedir = "os.homedir" ascii wide
        
    condition:
        // High confidence: GitHub credential access + file reading
        (any of ($gitconfig, $github_token, $gh_token, $github_auth, $git_credentials, $ssh_dir, $id_rsa, $id_ed25519)) and
        (any of ($read_file, $read_file_sync, $fs_read, $path_join, $os_homedir)) and
        (any of ($github_api, $github_token_auth, $github_bearer, $github_auth_header, $git_config, $git_remote, $git_url, $ssh_key))
}

rule GlassWorm_OpenVSX_Credential_Harvesting {
    meta:
        description = "Detects OpenVSX credential harvesting patterns"
        severity = "high"
        score = "80"
        author = "Kirin Scanner (by Knostic)  - GlassWorm Detection Suite"
        date = "2025-10-18"
    
    strings:
        // OpenVSX credential patterns
        $openvsx_token = "OPENVSX_TOKEN" ascii wide
        $openvsx_auth = "openvsx_auth" ascii wide
        $openvsx_pat = "OPENVSX_PAT" ascii wide
        
        // OpenVSX API endpoints
        $openvsx_api = "open-vsx.org" ascii wide
        $openvsx_publish = "publish" ascii wide
        $openvsx_upload = "upload" ascii wide
        
        // VS Code extension publishing
        $vsce_publish = "vsce publish" ascii wide
        $vsce_package = "vsce package" ascii wide
        $extension_publish = "extension publish" ascii wide
        
        // Authentication headers
        $auth_header = "Authorization" ascii wide
        $bearer_token = "Bearer" ascii wide
        $api_key = "api-key" ascii wide
        
    condition:
        // Detect OpenVSX credential access with publishing capabilities
        (any of ($openvsx_token, $openvsx_auth, $openvsx_pat)) and
        (any of ($openvsx_api, $openvsx_publish, $openvsx_upload, $vsce_publish, $vsce_package, $extension_publish)) and
        (any of ($auth_header, $bearer_token, $api_key))
}

rule GlassWorm_SSH_Credential_Harvesting {
    meta:
        description = "Detects SSH credential harvesting patterns"
        severity = "high"
        score = "90"
        author = "Kirin Scanner (by Knostic)  - GlassWorm Detection Suite"
        date = "2025-10-18"
    
    strings:
        // SSH key file paths
        $ssh_dir = ".ssh" ascii wide
        $id_rsa = "id_rsa" ascii wide
        $id_ed25519 = "id_ed25519" ascii wide
        $id_ecdsa = "id_ecdsa" ascii wide
        $id_dsa = "id_dsa" ascii wide
        $known_hosts = "known_hosts" ascii wide
        $ssh_config = "config" ascii wide
        
        // SSH key patterns
        $ssh_private = "BEGIN PRIVATE KEY" ascii wide
        $ssh_rsa = "BEGIN RSA PRIVATE KEY" ascii wide
        $ssh_ed25519 = "BEGIN OPENSSH PRIVATE KEY" ascii wide
        
        // File system access
        $read_file = "readFile" ascii wide
        $read_file_sync = "readFileSync" ascii wide
        $fs_read = "fs.read" ascii wide
        $path_join = "path.join" ascii wide
        $os_homedir = "os.homedir" ascii wide
        
        // SSH key usage
        $ssh_agent = "ssh-agent" ascii wide
        $ssh_add = "ssh-add" ascii wide
        $ssh_keygen = "ssh-keygen" ascii wide
        
    condition:
        // High confidence: SSH key access + file reading
        (any of ($ssh_dir, $id_rsa, $id_ed25519, $id_ecdsa, $id_dsa, $known_hosts, $ssh_config)) and
        (any of ($read_file, $read_file_sync, $fs_read, $path_join, $os_homedir)) and
        (any of ($ssh_private, $ssh_rsa, $ssh_ed25519, $ssh_agent, $ssh_add, $ssh_keygen))
}

rule GlassWorm_Credential_Exfiltration {
    meta:
        description = "Detects credential exfiltration patterns"
        severity = "high"
        score = "85"
        author = "Kirin Scanner (by Knostic)  - GlassWorm Detection Suite"
        date = "2025-10-18"
    
    strings:
        // Network exfiltration
        $http_post = "POST" ascii wide
        $https_post = "https" ascii wide
        $fetch_post = "fetch(" ascii wide
        $axios_post = "axios.post" ascii wide
        $request_post = "request.post" ascii wide
        
        // Data encoding for exfiltration
        $base64_encode = "btoa(" ascii wide
        $base64_encode_buf = "Buffer.from" ascii wide
        $json_stringify = "JSON.stringify" ascii wide
        
        // Credential data patterns
        $token_data = "token" ascii wide
        $auth_data = "auth" ascii wide
        $credential_data = "credential" ascii wide
        $password_data = "password" ascii wide
        $key_data = "key" ascii wide
        
        // Exfiltration endpoints
        $external_url = /https?:\/\/[a-z0-9\-\.]+\.[a-z]{2,}/ ascii wide
        $ip_address = /\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/ ascii wide
        
    condition:
        // Detect credential data with network exfiltration
        (any of ($http_post, $https_post, $fetch_post, $axios_post, $request_post)) and
        (any of ($base64_encode, $base64_encode_buf, $json_stringify)) and
        (any of ($token_data, $auth_data, $credential_data, $password_data, $key_data)) and
        (any of ($external_url, $ip_address))
}
