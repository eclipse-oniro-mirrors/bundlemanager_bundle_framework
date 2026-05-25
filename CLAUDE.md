# BundleManager Bundle Framework

This is the **BundleManager Bundle Framework** component of OpenHarmony, a core subsystem responsible for application bundle management. It provides capabilities for application installation, update, uninstallation, and information query.

## Overview

This framework manages OpenHarmony application packages (HAP files), handling their entire lifecycle from installation to removal. It operates as a multi-process architecture with privilege separation between the BundleMgrService (SA 401) and InstalldService (SA 511).

## Directory Structure

```
bundlemanager_bundle_framework/
├── common/                    # Common utilities (logging)
├── interfaces/                # Interface layer
│   ├── inner_api/             # Internal APIs for other subsystems
│   │   ├── appexecfwk_base/   # Base types and error codes
│   │   ├── appexecfwk_core/   # Core bundle manager interfaces
│   │   └── bundlemgr_extension/ # Extension interfaces
│   └── kits/                  # Application development interfaces
│       ├── native/            # C/C++ APIs
│       ├── js/                # JavaScript/N-API bindings
│       ├── ani/               # ANI (Ark Native Interface) bindings
│       └── cj/                # Cangjie language bindings
├── services/                  # Service implementations
│   └── bundlemgr/             # Bundle manager service (SA 401)
│       ├── include/           # Header files (organized like src/)
│       └── src/               # Source code organized by module
├── test/                      # System/integration tests
├── etc/                       # Configuration files
└── sa_profile/                # System ability profiles
```

## Key Service Modules (services/bundlemgr/src/)

**Core Components:**
- `bundle_mgr_service.cpp` - Main BundleMgrService implementation (SA 401)
- `bundle_data_mgr.cpp` - Central data manager for bundle information
- `bundle_installer.cpp` - Installation/uninstallation logic
- `bundle_mgr_host_impl.cpp` - IPC host for IBundleMgr interface

**Functional Modules:**
- `aging/` - Bundle aging management for resource cleanup
- `aot/` - Ahead-of-time compilation management
- `app_control/` - Application control and jump interception
- `app_provision_info/` - Provisioning profile management
- `app_service_fwk/` - Application service framework installation
- `bms_extension/` - BMS extension client
- `bundle_backup/` - Backup and restore functionality
- `bundle_resource/` - Resource management
- `bundlemgr_ext/` - BundleManager extensions
- `clone/` - Application clone support
- `common/` - Shared utilities
- `data/` - Data processing
- `default_app/` - Default application management
- `distributed_manager/` - Distributed bundle management
- `driver/` - Driver installation support
- `exception/` - Exception handling utilities
- `extend_resource/` - Extended resource management
- `first_install_data_mgr/` - First installation data management
- `free_install/` - Free installation (on-demand) capability
- `idle_condition_mgr/` - Idle condition management
- `installd/` - Installd client (IPC with SA 511)
- `ipc/` - IPC communication with InstalldService
- `navigation/` - Navigation data management
- `on_demand_install/` - On-demand installation
- `overlay/` - Overlay installation support
- `plugin/` - Plugin support
- `quick_fix/` - Quick fix (patch) management
- `rdb/` - Relational database wrapper
- `sandbox_app/` - Sandbox application support
- `shared/` - Shared bundle management
- `uninstall_data_mgr/` - Uninstallation data management
- `user_auth/` - User authentication
- `verify/` - Verification and code signing

## Build System

**Build Tool:** GN (Generate Ninja)

**Key Build Files:**
- `BUILD.gn` - Root build configuration
- `services/bundlemgr/BUILD.gn` - Service layer build
- `appexecfwk.gni` - Global configuration
- `services/bundlemgr/appexecfwk_bundlemgr.gni` - Service configuration

**Common Build Commands:**
```bash
# Build all bundle framework targets
./build.sh --product-name rk3568 --build-target bundle_framework

# Build only service layer
./build.sh --product-name rk3568 --build-target services/bundlemgr:bms_target

# Build with feature enabled
./build.sh --product-name rk3568 --build-target bundle_framework --gn-args bundle_framework_free_install=true
```

**Feature Flags (appexecfwk.gni):**
- `bundle_framework_free_install` - Free installation capability
- `bundle_framework_default_app` - Default application management
- `bundle_framework_quick_fix` - Quick fix support
- `bundle_framework_overlay_install` - Overlay installation
- `bundle_framework_sandbox_app` - Sandbox application support
- `bundle_framework_graphics` - Graphics-related features
- `bundle_framework_launcher` - Launcher service capabilities

## Development Patterns

### Logging

**Location:** `common/log/`

**Usage in .gn file:**
```gn
defines = [
    "APP_LOG_TAG = \"BMS\"",
    "LOG_DOMAIN = 0xD001120",
]
deps = [ "${common_path}/log:appexecfwk_log_source_set" ]
```

**In code:**
```cpp
#include "app_log_wrapper.h"

// Dynamic log level control
AppLogWrapper::SetLogLevel(AppLogLevel::DEBUG);

// Logging macros
APP_LOGD("Debug: %{public}d", 123);                      // Debug
APP_LOGI("Info: %{public}s", "string");                  // Info
APP_LOGW("Warning");                                      // Warning
APP_LOGE("Error: %{private}s", "sensitive");             // Error
```

**Note:** Use `%{public}` for non-sensitive data and `%{private}` for sensitive data in log messages.

### Error Handling

**Error Codes:** Defined in `interfaces/inner_api/appexecfwk_base/include/appexecfwk_errors.h`
- Format: Module-specific offsets from base error codes
- Categories: Common, AppMgr, BundleMgr, Install, Database, Code Signing, QuickFix, Overlay

**Error Checking Macros:** `services/bundlemgr/src/common/common_fun_ani.h`
```cpp
RETURN_IF_NULL(ptr);
RETURN_FALSE_IF_NULL(ptr);
```

**Error Mapping Patterns:**
- `RDB_ERR_MAP` - Database error mapping
- `CODE_SIGNATURE_ERR_MAP` - Code signing error mapping

### Data Storage

**Technology:** RDB (Relational Database)

**Key Files:**
- Interface: `services/bundlemgr/include/bundle_data_storage_interface.h`
- Implementation: `services/bundlemgr/src/rdb/`

## Process Architecture

### BundleMgrService (SA 401)
- **Process:** Foundation process
- **Function:** Core APIs for bundle management
- **Log Domain:** 0xD001120
- **Depends On:**
  - Common event service
  - Bundle proxy service
  - EL5 file encryption key service
  - InstalldService (SA 511)

### InstalldService (SA 511)
- **Process:** Installs process (privileged)
- **Configuration:** `sa_profile/511.json`
- **Function:** File system operations requiring elevated privileges
- **Auto-unload:** After 180 seconds of inactivity

## Testing

**Test Structure:**
- `test/unittest/` - Unit tests
- `test/moduletest/` - Module integration tests
- `test/systemtest/` - End-to-end tests
- `test/benchmarktest/` - Performance tests
- `test/fuzztest/` - Fuzzing tests

**Build Tests:**
```bash
./build.sh --product-name rk3568 --build-target test_target
```

## Important Concepts

- **Bundle:** Application package (HAP file)
- **HAP:** Harmony Ability Package - OpenHarmony application format
- **Module:** HAP containing one or more Abilities
- **Ability:** Application component representing functionality
- **InnerBundleInfo:** Internal bundle information representation
- **ApplicationInfo:** Application-level information
- **AbilityInfo:** Component-level information

## Key Dependencies

(See `bundle.json` for complete list)
- `ability_runtime` - Ability framework
- `samgr` - System ability manager
- `ipc` - IPC framework
- `storage_service` - File storage
- `access_token` - Permission management
- `resource_manager` - Resource management
- `appverify` - Application verification
- `hilog`, `hisysevent`, `hitrace` - DFX capabilities

## Debugging

**View Logs:**
```bash
hdc shell hilog -T BMS
```

**Check Service Status:**
```bash
hdc shell hidumper -s 401  # BundleMgrService
hdc shell hidumper -s 511  # InstalldService
```

**View HiSysEvents:**
```bash
hdc shell hidumper -s 1201 -a "-e BMS"
hdc shell hisysevent -q -d BMS_INSTALL -t 100
```

**Common Debugging Scenarios:**
1. Installation failures: Check InstalldService status, signature verification, disk space
2. Permission issues: Verify access token grants, provisioning profile parsing
3. IPC communication: Verify both SA 401 and SA 511 are running
4. Database issues: Check RDB initialization, schema, transaction failures

## Code Style Notes

- File header includes Apache 2.0 license notice
- C++ namespace: `OHOS`
- Class naming: PascalCase (e.g., `BundleMgrService`)
- Method naming: PascalCase for public, camelCase for private
- File naming: snake_case (e.g., `bundle_mgr_service.cpp`)
- Header guards: `FOUNDATION_APPEXECFWK_..._H` format