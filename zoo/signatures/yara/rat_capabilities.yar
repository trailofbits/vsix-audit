/*
    GlassWorm RAT Capabilities Detection
    Detects Remote Access Trojan patterns including SOCKS proxy, VNC, and remote execution
    Based on GlassWorm RAT capabilities for persistent access
*/

rule GlassWorm_SOCKS_Proxy_Deployment {
    meta:
        description = "Detects SOCKS proxy server deployment patterns"
        severity = "high"
        score = "85"
        author = "Kirin Scanner (by Knostic)  - GlassWorm Detection Suite"
        date = "2025-10-18"
        reference = "https://www.koi.ai/blog/glassworm-first-self-propagating-worm-using-invisible-code-hits-openvsx-marketplace"
    
    strings:
        // SOCKS proxy patterns
        $socks_proxy = "socks" nocase ascii wide
        $socks_server = "socksServer" ascii wide
        $socks_proxy_server = "socksProxyServer" ascii wide
        $socks5 = "socks5" nocase ascii wide
        $socks4 = "socks4" nocase ascii wide
        
        // Network server creation
        $create_server = "createServer" ascii wide
        $net_create_server = "net.createServer" ascii wide
        $http_create_server = "http.createServer" ascii wide
        $https_create_server = "https.createServer" ascii wide
        
        // Proxy configuration
        $proxy_config = "proxyConfig" ascii wide
        $proxy_server = "proxyServer" ascii wide
        $proxy_port = "proxyPort" ascii wide
        $proxy_host = "proxyHost" ascii wide
        
        // Network binding
        $listen = "listen" ascii wide
        $bind = "bind" ascii wide
        $port = "port" ascii wide
        $host = "host" ascii wide
        
        // SOCKS protocol
        $socks_auth = "socksAuth" ascii wide
        $socks_connect = "socksConnect" ascii wide
        $socks_relay = "socksRelay" ascii wide
        
    condition:
        // High confidence: SOCKS proxy + server creation + network binding
        (any of ($socks_proxy, $socks_server, $socks_proxy_server, $socks5, $socks4)) and
        (any of ($create_server, $net_create_server, $http_create_server, $https_create_server)) and
        (any of ($listen, $bind, $port, $host, $proxy_config, $proxy_server, $proxy_port, $proxy_host, $socks_auth, $socks_connect, $socks_relay))
}

rule GlassWorm_VNC_Installation {
    meta:
        description = "Detects VNC/HVNC installation and usage patterns"
        severity = "high"
        score = "90"
        author = "Kirin Scanner (by Knostic)  - GlassWorm Detection Suite"
        date = "2025-10-18"
    
    strings:
        // VNC patterns
        $vnc = "vnc" nocase ascii wide
        $hvnc = "hvnc" nocase ascii wide
        $tightvnc = "tightvnc" nocase ascii wide
        $ultravnc = "ultravnc" nocase ascii wide
        $realvnc = "realvnc" nocase ascii wide
        
        // VNC installation
        $vnc_install = "vncInstall" ascii wide
        $vnc_setup = "vncSetup" ascii wide
        $vnc_configure = "vncConfigure" ascii wide
        $vnc_start = "vncStart" ascii wide
        
        // VNC server
        $vnc_server = "vncServer" ascii wide
        $vnc_daemon = "vncDaemon" ascii wide
        $vnc_service = "vncService" ascii wide
        
        // Remote desktop access
        $remote_desktop = "remoteDesktop" ascii wide
        $desktop_sharing = "desktopSharing" ascii wide
        $screen_sharing = "screenSharing" ascii wide
        $remote_access = "remoteAccess" ascii wide
        
        // VNC configuration
        $vnc_password = "vncPassword" ascii wide
        $vnc_port = "vncPort" ascii wide
        $vnc_display = "vncDisplay" ascii wide
        
    condition:
        // High confidence: VNC installation + server setup + remote access
        (any of ($vnc, $hvnc, $tightvnc, $ultravnc, $realvnc)) and
        (any of ($vnc_install, $vnc_setup, $vnc_configure, $vnc_start, $vnc_server, $vnc_daemon, $vnc_service)) and
        (any of ($remote_desktop, $desktop_sharing, $screen_sharing, $remote_access, $vnc_password, $vnc_port, $vnc_display))
}

rule GlassWorm_Remote_Command_Execution {
    meta:
        description = "Detects remote command execution infrastructure"
        severity = "critical"
        score = "95"
        author = "Kirin Scanner (by Knostic)  - GlassWorm Detection Suite"
        date = "2025-10-18"
    
    strings:
        // Command execution patterns
        $exec = "exec" ascii wide
        $spawn = "spawn" ascii wide
        $execFile = "execFile" ascii wide
        $execSync = "execSync" ascii wide
        
        // Child process creation
        $child_process = "child_process" ascii wide
        $fork = "fork" ascii wide
        $spawn_process = "spawnProcess" ascii wide
        
        // Remote command execution
        $remote_exec = "remoteExec" ascii wide
        $remote_command = "remoteCommand" ascii wide
        $remote_shell = "remoteShell" ascii wide
        $remote_cmd = "remoteCmd" ascii wide
        
        // Command and control
        $command_control = "commandControl" ascii wide
        $cmd_control = "cmdControl" ascii wide
        $shell_control = "shellControl" ascii wide
        
        // Network command execution
        $net_exec = "netExec" ascii wide
        $socket_exec = "socketExec" ascii wide
        $tcp_exec = "tcpExec" ascii wide
        
        // Command parsing
        $parse_command = "parseCommand" ascii wide
        $execute_command = "executeCommand" ascii wide
        $run_command = "runCommand" ascii wide
        
    condition:
        // Critical: Command execution + remote capabilities + network communication
        (any of ($exec, $spawn, $execFile, $execSync, $child_process, $fork, $spawn_process)) and
        (any of ($remote_exec, $remote_command, $remote_shell, $remote_cmd, $command_control, $cmd_control, $shell_control)) and
        (any of ($net_exec, $socket_exec, $tcp_exec, $parse_command, $execute_command, $run_command))
}

rule GlassWorm_Persistent_Backdoor {
    meta:
        description = "Detects persistent backdoor mechanisms"
        severity = "high"
        score = "90"
        author = "Kirin Scanner (by Knostic)  - GlassWorm Detection Suite"
        date = "2025-10-18"
    
    strings:
        // Persistence mechanisms
        $persistence = "persistence" ascii wide
        $backdoor = "backdoor" ascii wide
        $persistent = "persistent" ascii wide
        $survive_reboot = "surviveReboot" ascii wide
        
        // Registry persistence (Windows)
        $reg_run = "regRun" ascii wide
        $registry_run = "registryRun" ascii wide
        $startup_key = "startupKey" ascii wide
        $auto_start = "autoStart" ascii wide
        
        // Service installation
        $service_install = "serviceInstall" ascii wide
        $service_create = "serviceCreate" ascii wide
        $service_start = "serviceStart" ascii wide
        $service_auto = "serviceAuto" ascii wide
        
        // Scheduled tasks
        $scheduled_task = "scheduledTask" ascii wide
        $cron_job = "cronJob" ascii wide
        $task_scheduler = "taskScheduler" ascii wide
        
        // Startup folder
        $startup_folder = "startupFolder" ascii wide
        $startup_shortcut = "startupShortcut" ascii wide
        $startup_link = "startupLink" ascii wide
        
        // Hidden files
        $hidden_file = "hiddenFile" ascii wide
        $system_file = "systemFile" ascii wide
        $temp_file = "tempFile" ascii wide
        
    condition:
        // High confidence: Persistence + registry/service manipulation + hidden files
        (any of ($persistence, $backdoor, $persistent, $survive_reboot)) and
        (any of ($reg_run, $registry_run, $startup_key, $auto_start, $service_install, $service_create, $service_start, $service_auto, $scheduled_task, $cron_job, $task_scheduler)) and
        (any of ($startup_folder, $startup_shortcut, $startup_link, $hidden_file, $system_file, $temp_file))
}

rule GlassWorm_Network_Reconnaissance {
    meta:
        description = "Detects network reconnaissance and lateral movement patterns"
        severity = "medium"
        score = "75"
        author = "Kirin Scanner (by Knostic)  - GlassWorm Detection Suite"
        date = "2025-10-18"
    
    strings:
        // Network scanning
        $network_scan = "networkScan" ascii wide
        $port_scan = "portScan" ascii wide
        $host_scan = "hostScan" ascii wide
        $network_discovery = "networkDiscovery" ascii wide
        
        // Network enumeration
        $enumerate_hosts = "enumerateHosts" ascii wide
        $discover_hosts = "discoverHosts" ascii wide
        $scan_network = "scanNetwork" ascii wide
        $map_network = "mapNetwork" ascii wide
        
        // Lateral movement
        $lateral_movement = "lateralMovement" ascii wide
        $pivot = "pivot" ascii wide
        $jump_host = "jumpHost" ascii wide
        $relay = "relay" ascii wide
        
        // Network tools
        $nmap = "nmap" ascii wide
        $ping = "ping" ascii wide
        $traceroute = "traceroute" ascii wide
        $netstat = "netstat" ascii wide
        
        // Network protocols
        $tcp_scan = "tcpScan" ascii wide
        $udp_scan = "udpScan" ascii wide
        $icmp_scan = "icmpScan" ascii wide
        
    condition:
        // Detect network reconnaissance with scanning tools
        (any of ($network_scan, $port_scan, $host_scan, $network_discovery, $enumerate_hosts, $discover_hosts, $scan_network, $map_network)) and
        (any of ($lateral_movement, $pivot, $jump_host, $relay, $nmap, $ping, $traceroute, $netstat)) and
        (any of ($tcp_scan, $udp_scan, $icmp_scan))
}
