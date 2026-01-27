/*
    GlassWorm Self-Propagation Detection
    Detects worm self-propagation patterns including automated publishing and credential reuse
    Based on GlassWorm worm behavior for autonomous spread
*/

rule GlassWorm_Automated_Package_Publishing {
    meta:
        description = "Detects automated package publishing using stolen credentials"
        severity = "high"
        score = "85"
        author = "Kirin Scanner - GlassWorm Detection Suite"
        date = "2025-10-18"
        reference = "https://www.koi.ai/blog/glassworm-first-self-propagating-worm-using-invisible-code-hits-openvsx-marketplace"

    strings:
        // Package publishing
        $npm_publish = "npm publish" ascii wide
        $yarn_publish = "yarn publish" ascii wide
        $publish_package = "publishPackage" ascii wide
        $auto_publish = "autoPublish" ascii wide

        // Extension publishing
        $vsce_publish = "vsce publish" ascii wide
        $extension_publish = "extensionPublish" ascii wide
        $marketplace_publish = "marketplacePublish" ascii wide
        $openvsx_publish = "openvsxPublish" ascii wide

        // Automated publishing
        $automated_publish = "automatedPublish" ascii wide
        $auto_upload = "autoUpload" ascii wide
        $batch_publish = "batchPublish" ascii wide
        $mass_publish = "massPublish" ascii wide

        // Credential usage
        $use_credentials = "useCredentials" ascii wide
        $auth_publish = "authPublish" ascii wide
        $token_publish = "tokenPublish" ascii wide
        $credential_publish = "credentialPublish" ascii wide

        // Publishing APIs
        $npm_api = "npmApi" ascii wide
        $github_api = "githubApi" ascii wide
        $openvsx_api = "openvsxApi" ascii wide
        $marketplace_api = "marketplaceApi" ascii wide

    condition:
        // High confidence: Automated publishing + credential usage + API access
        (any of ($npm_publish, $yarn_publish, $publish_package, $auto_publish, $vsce_publish, $extension_publish, $marketplace_publish, $openvsx_publish)) and
        (any of ($automated_publish, $auto_upload, $batch_publish, $mass_publish)) and
        (any of ($use_credentials, $auth_publish, $token_publish, $credential_publish, $npm_api, $github_api, $openvsx_api, $marketplace_api))
}

rule GlassWorm_Credential_Reuse {
    meta:
        description = "Detects credential reuse for additional compromises"
        severity = "high"
        score = "80"
        author = "Kirin Scanner - GlassWorm Detection Suite"
        date = "2025-10-18"

    strings:
        // Credential validation
        $validate_credentials = "validateCredentials" ascii wide
        $test_credentials = "testCredentials" ascii wide
        $check_credentials = "checkCredentials" ascii wide
        $verify_credentials = "verifyCredentials" ascii wide

        // Credential reuse
        $reuse_credentials = "reuseCredentials" ascii wide
        $credential_reuse = "credentialReuse" ascii wide
        $reuse_auth = "reuseAuth" ascii wide
        $reuse_token = "reuseToken" ascii wide

        // Multiple account access
        $multi_account = "multiAccount" ascii wide
        $batch_account = "batchAccount" ascii wide
        $bulk_account = "bulkAccount" ascii wide
        $mass_account = "massAccount" ascii wide

        // Account enumeration
        $enumerate_accounts = "enumerateAccounts" ascii wide
        $list_accounts = "listAccounts" ascii wide
        $scan_accounts = "scanAccounts" ascii wide
        $discover_accounts = "discoverAccounts" ascii wide

        // Credential rotation
        $rotate_credentials = "rotateCredentials" ascii wide
        $credential_rotation = "credentialRotation" ascii wide
        $auth_rotation = "authRotation" ascii wide

    condition:
        // Detect credential validation with reuse patterns
        (any of ($validate_credentials, $test_credentials, $check_credentials, $verify_credentials)) and
        (any of ($reuse_credentials, $credential_reuse, $reuse_auth, $reuse_token)) and
        (any of ($multi_account, $batch_account, $bulk_account, $mass_account, $enumerate_accounts, $list_accounts, $scan_accounts, $discover_accounts, $rotate_credentials, $credential_rotation, $auth_rotation))
}

rule GlassWorm_Git_Automation {
    meta:
        description = "Detects automated git operations for spreading malicious code"
        severity = "high"
        score = "85"
        author = "Kirin Scanner - GlassWorm Detection Suite"
        date = "2025-10-18"

    strings:
        // Git automation
        $git_automation = "gitAutomation" ascii wide
        $auto_git = "autoGit" ascii wide
        $git_bot = "gitBot" ascii wide
        $automated_git = "automatedGit" ascii wide

        // Git operations
        $git_commit = "git commit" ascii wide
        $git_push = "git push" ascii wide
        $git_pull = "git pull" ascii wide
        $git_clone = "git clone" ascii wide

        // Automated git workflow
        $git_workflow = "gitWorkflow" ascii wide
        $auto_commit = "autoCommit" ascii wide
        $auto_push = "autoPush" ascii wide
        $batch_git = "batchGit" ascii wide

        // Repository manipulation
        $repo_manipulate = "repoManipulate" ascii wide
        $repo_inject = "repoInject" ascii wide
        $repo_contaminate = "repoContaminate" ascii wide
        $repo_infect = "repoInfect" ascii wide

        // Git hooks
        $git_hooks = "gitHooks" ascii wide
        $pre_commit = "preCommit" ascii wide
        $post_commit = "postCommit" ascii wide
        $pre_push = "prePush" ascii wide

    condition:
        // Detect git automation with repository manipulation
        (any of ($git_automation, $auto_git, $git_bot, $automated_git, $git_commit, $git_push, $git_pull, $git_clone)) and
        (any of ($git_workflow, $auto_commit, $auto_push, $batch_git)) and
        (any of ($repo_manipulate, $repo_inject, $repo_contaminate, $repo_infect, $git_hooks, $pre_commit, $post_commit, $pre_push))
}

rule GlassWorm_Worm_Propagation {
    meta:
        description = "Detects worm propagation mechanisms"
        severity = "critical"
        score = "95"
        author = "Kirin Scanner - GlassWorm Detection Suite"
        date = "2025-10-18"

    strings:
        // Worm patterns
        $worm = "worm" ascii wide
        $propagate = "propagate" ascii wide
        $spread = "spread" ascii wide
        $infect = "infect" ascii wide

        // Self-replication
        $self_replicate = "selfReplicate" ascii wide
        $self_copy = "selfCopy" ascii wide
        $self_propagate = "selfPropagate" ascii wide
        $auto_replicate = "autoReplicate" ascii wide

        // Propagation vectors
        $propagation_vector = "propagationVector" ascii wide
        $spread_vector = "spreadVector" ascii wide
        $infection_vector = "infectionVector" ascii wide
        $attack_vector = "attackVector" ascii wide

        // Autonomous behavior
        $autonomous = "autonomous" ascii wide
        $self_sustaining = "selfSustaining" ascii wide
        $self_contained = "selfContained" ascii wide
        $independent = "independent" ascii wide

        // Worm lifecycle
        $worm_lifecycle = "wormLifecycle" ascii wide
        $infection_cycle = "infectionCycle" ascii wide
        $propagation_cycle = "propagationCycle" ascii wide
        $spread_cycle = "spreadCycle" ascii wide

    condition:
        // Critical: Worm behavior + self-replication + autonomous operation
        (any of ($worm, $propagate, $spread, $infect)) and
        (any of ($self_replicate, $self_copy, $self_propagate, $auto_replicate)) and
        (any of ($propagation_vector, $spread_vector, $infection_vector, $attack_vector, $autonomous, $self_sustaining, $self_contained, $independent, $worm_lifecycle, $infection_cycle, $propagation_cycle, $spread_cycle))
}

rule GlassWorm_Supply_Chain_Abuse {
    meta:
        description = "Detects supply chain abuse for worm propagation"
        severity = "high"
        score = "90"
        author = "Kirin Scanner - GlassWorm Detection Suite"
        date = "2025-10-18"

    strings:
        // Supply chain patterns
        $supply_chain = "supplyChain" ascii wide
        $package_chain = "packageChain" ascii wide
        $dependency_chain = "dependencyChain" ascii wide
        $repo_chain = "repoChain" ascii wide

        // Package ecosystem abuse
        $ecosystem_abuse = "ecosystemAbuse" ascii wide
        $package_abuse = "packageAbuse" ascii wide
        $registry_abuse = "registryAbuse" ascii wide
        $marketplace_abuse = "marketplaceAbuse" ascii wide

        // Dependency injection
        $dependency_inject = "dependencyInject" ascii wide
        $package_inject = "packageInject" ascii wide
        $repo_inject = "repoInject" ascii wide
        $chain_inject = "chainInject" ascii wide

        // Automated compromise
        $auto_compromise = "autoCompromise" ascii wide
        $batch_compromise = "batchCompromise" ascii wide
        $mass_compromise = "massCompromise" ascii wide
        $bulk_compromise = "bulkCompromise" ascii wide

        // Trust exploitation
        $trust_exploit = "trustExploit" ascii wide
        $trust_abuse = "trustAbuse" ascii wide
        $reputation_abuse = "reputationAbuse" ascii wide
        $legitimacy_abuse = "legitimacyAbuse" ascii wide

    condition:
        // Detect supply chain abuse with automated compromise
        (any of ($supply_chain, $package_chain, $dependency_chain, $repo_chain)) and
        (any of ($ecosystem_abuse, $package_abuse, $registry_abuse, $marketplace_abuse)) and
        (any of ($dependency_inject, $package_inject, $repo_inject, $chain_inject, $auto_compromise, $batch_compromise, $mass_compromise, $bulk_compromise, $trust_exploit, $trust_abuse, $reputation_abuse, $legitimacy_abuse))
}
