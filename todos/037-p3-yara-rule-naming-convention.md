# P3: YARA rule naming convention inconsistency

## Problem

New YARA rules in this PR use inconsistent naming conventions. Some rules include a language tag (e.g., `_JS_`) while others do not. The existing convention in the codebase appears to use `VSIX_{LANG}_{Description}` format.

8 of 9 new rules omit the `_JS_` language tag present in all existing rules. The one rule that includes it (`C2_JS_Ethereum_Contract_C2_Feb26`) has a redundant `C2` — appears as both prefix and description.

Missing language tag examples:

- `SUSP_NativeAddon_Platform_Loader_Feb26` → `SUSP_JS_NativeAddon_Platform_Loader_Feb26`
- `LOADER_RMM_ScreenConnect_Delivery_Feb26` → `LOADER_JS_RMM_ScreenConnect_Delivery_Feb26`

Redundant naming:

- `C2_JS_Ethereum_Contract_C2_Feb26` → `C2_JS_Ethereum_Contract_Feb26`

Also: the YARA README documents `{campaign}_{detection_type}.yar` as the file naming convention, but new files use `{detection_category}_{target}.yar`. Either update the README or align file names.

## Location

- `zoo/signatures/yara/blockchain_c2_extended.yar`
- `zoo/signatures/yara/native_addon_loader.yar`
- `zoo/signatures/yara/persistence_macos.yar`
- `zoo/signatures/yara/rmm_tool_delivery.yar`
- `zoo/signatures/yara/README.md`

## Fix

Review and align rule names with the established naming convention. Use `/yara-rule-authoring` skill to confirm the expected format. Update the YARA README if the naming convention has intentionally evolved.

## Severity

P3 - Convention inconsistency, no functional impact.
