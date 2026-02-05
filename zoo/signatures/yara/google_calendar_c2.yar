/*
    GlassWorm Google Calendar C2 Detection
    Detects Google Calendar API usage for command and control fallback
    Based on GlassWorm using Google Calendar as backup C2 channel
*/

rule C2_JS_GlassWorm_Google_Calendar_Jan25 {
  meta:
    description = "Detects GlassWorm-style Google Calendar API usage for command and control fallback channel"
    severity    = "high"
    score       = "80"
    author      = "vsix-audit"
    date        = "2025-01-29"
    reference   = "https://www.koi.security/blog/glassworm-first-self-propagating-worm-using-invisible-code-hits-openvsx-marketplace"

  strings:
    // Google Calendar API
    $google_calendar = "google-calendar" ascii wide
    $calendar_api    = "calendarApi" ascii wide
    $gcal_api        = "gcalApi" ascii wide
    $calendar_google = "calendar.google" ascii wide

    // Calendar API endpoints
    $calendar_app        = "calendar.app.google" ascii wide
    $googleapis_calendar = "googleapis.com/calendar" ascii wide
    $calendar_v3         = "calendar/v3" ascii wide
    $calendar_events     = "calendar/events" ascii wide

    // Calendar authentication
    $calendar_auth  = "calendarAuth" ascii wide
    $gcal_auth      = "gcalAuth" ascii wide
    $calendar_token = "calendarToken" ascii wide
    $calendar_oauth = "calendarOAuth" ascii wide

    // Calendar event access
    $calendar_events_list = "calendarEvents" ascii wide
    $event_list           = "eventList" ascii wide
    $get_events           = "getEvents" ascii wide
    $list_events          = "listEvents" ascii wide

    // Event parsing
    $parse_events    = "parseEvents" ascii wide
    $event_parser    = "eventParser" ascii wide
    $calendar_parser = "calendarParser" ascii wide
    $event_data      = "eventData" ascii wide

  condition:
    // High confidence: Google Calendar API + event access + parsing
    (any of ($google_calendar, $calendar_api, $gcal_api, $calendar_google, $calendar_app, $googleapis_calendar, $calendar_v3, $calendar_events)) and
    (any of ($calendar_auth, $gcal_auth, $calendar_token, $calendar_oauth)) and
    (any of ($calendar_events_list, $event_list, $get_events, $list_events, $parse_events, $event_parser, $calendar_parser, $event_data))
}

rule C2_JS_GlassWorm_Calendar_Commands_Jan25 {
  meta:
    description = "Detects GlassWorm-style calendar event parsing used to receive and execute C2 commands"
    severity    = "high"
    score       = "85"
    author      = "vsix-audit"
    date        = "2025-01-29"
    reference   = "https://www.koi.security/blog/glassworm-first-self-propagating-worm-using-invisible-code-hits-openvsx-marketplace"

  strings:
    // Event command parsing
    $event_commands    = "eventCommands" ascii wide
    $calendar_commands = "calendarCommands" ascii wide
    $parse_commands    = "parseCommands" ascii wide
    $command_parser    = "commandParser" ascii wide

    // Event data extraction
    $event_summary     = "eventSummary" ascii wide
    $event_description = "eventDescription" ascii wide
    $event_title       = "eventTitle" ascii wide
    $event_content     = "eventContent" ascii wide

    // Command execution from events
    $execute_command = "executeCommand" ascii wide
    $run_command     = "runCommand" ascii wide
    $command_exec    = "commandExec" ascii wide
    $exec_from_event = "execFromEvent" ascii wide

    // Event monitoring
    $monitor_events   = "monitorEvents" ascii wide
    $watch_events     = "watchEvents" ascii wide
    $event_watcher    = "eventWatcher" ascii wide
    $calendar_monitor = "calendarMonitor" ascii wide

    // Event filtering
    $filter_events  = "filterEvents" ascii wide
    $event_filter   = "eventFilter" ascii wide
    $command_filter = "commandFilter" ascii wide
    $c2_filter      = "c2Filter" ascii wide

  condition:
    // Detect event command parsing with execution capabilities
    (any of ($event_commands, $calendar_commands, $parse_commands, $command_parser)) and
    (any of ($event_summary, $event_description, $event_title, $event_content)) and
    (any of ($execute_command, $run_command, $command_exec, $exec_from_event, $monitor_events, $watch_events, $event_watcher, $calendar_monitor, $filter_events, $event_filter, $command_filter, $c2_filter))
}

rule C2_JS_GlassWorm_Calendar_Backup_Jan25 {
  meta:
    description = "Detects GlassWorm-style calendar-based backup C2 mechanism with redundancy and failover patterns"
    severity    = "medium"
    score       = "70"
    author      = "vsix-audit"
    date        = "2025-01-29"
    reference   = "https://www.koi.security/blog/glassworm-first-self-propagating-worm-using-invisible-code-hits-openvsx-marketplace"

  strings:
    // Backup C2 patterns
    $backup_c2    = "backupC2" ascii wide
    $fallback_c2  = "fallbackC2" ascii wide
    $secondary_c2 = "secondaryC2" ascii wide
    $alternate_c2 = "alternateC2" ascii wide

    // C2 redundancy
    $c2_redundancy = "c2Redundancy" ascii wide
    $c2_backup     = "c2Backup" ascii wide
    $c2_failover   = "c2Failover" ascii wide
    $c2_resilience = "c2Resilience" ascii wide

    // Calendar C2
    $calendar_c2      = "calendarC2" ascii wide
    $gcal_c2          = "gcalC2" ascii wide
    $calendar_channel = "calendarChannel" ascii wide
    $event_c2         = "eventC2" ascii wide

    // C2 rotation
    $c2_rotation  = "c2Rotation" ascii wide
    $c2_switch    = "c2Switch" ascii wide
    $c2_alternate = "c2Alternate" ascii wide
    $c2_cycle     = "c2Cycle" ascii wide

    // C2 resilience
    $c2_persistence = "c2Persistence" ascii wide
    $c2_survival    = "c2Survival" ascii wide
    $c2_durability  = "c2Durability" ascii wide
    $c2_reliability = "c2Reliability" ascii wide

  condition:
    // Detect backup C2 with calendar integration
    (any of ($backup_c2, $fallback_c2, $secondary_c2, $alternate_c2, $c2_redundancy, $c2_backup, $c2_failover, $c2_resilience)) and
    (any of ($calendar_c2, $gcal_c2, $calendar_channel, $event_c2)) and
    (any of ($c2_rotation, $c2_switch, $c2_alternate, $c2_cycle, $c2_persistence, $c2_survival, $c2_durability, $c2_reliability))
}

rule C2_JS_GlassWorm_Calendar_Exfil_Jan25 {
  meta:
    description = "Detects GlassWorm-style data exfiltration using calendar events with encoded payloads"
    severity    = "medium"
    score       = "75"
    author      = "vsix-audit"
    date        = "2025-01-29"
    reference   = "https://www.koi.security/blog/glassworm-first-self-propagating-worm-using-invisible-code-hits-openvsx-marketplace"

  strings:
    // Event exfiltration
    $event_exfil         = "eventExfil" ascii wide
    $calendar_exfil      = "calendarExfil" ascii wide
    $event_data_exfil    = "eventDataExfil" ascii wide
    $calendar_data_exfil = "calendarDataExfil" ascii wide

    // Event creation for exfiltration
    $create_event = "createEvent" ascii wide
    $add_event    = "addEvent" ascii wide
    $insert_event = "insertEvent" ascii wide
    $post_event   = "postEvent" ascii wide

    // Data encoding in events
    $encode_in_event   = "encodeInEvent" ascii wide
    $event_encoding    = "eventEncoding" ascii wide
    $calendar_encoding = "calendarEncoding" ascii wide
    $event_base64      = "eventBase64" ascii wide

    // Event data patterns
    $event_payload    = "eventPayload" ascii wide
    $event_data       = "eventData" ascii wide
    $calendar_payload = "calendarPayload" ascii wide
    $event_content    = "eventContent" ascii wide

  condition:
    // Detect event-based exfiltration with data encoding
    (any of ($event_exfil, $calendar_exfil, $event_data_exfil, $calendar_data_exfil)) and
    (any of ($create_event, $add_event, $insert_event, $post_event)) and
    (any of ($encode_in_event, $event_encoding, $calendar_encoding, $event_base64, $event_payload, $event_data, $calendar_payload, $event_content))
}
