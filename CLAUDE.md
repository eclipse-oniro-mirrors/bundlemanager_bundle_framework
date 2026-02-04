# CLAUDE.md

This file provides guidance for Claude Code (claude.ai/code) when working in this codebase.

## Overview

This is the **BundleManager Bundle Framework** of OpenHarmony, a core subsystem responsible for application bundle management. It provides capabilities for application installation, update, uninstallation, and information query.

## Quick Start

### Prerequisites

This project is part of OpenHarmony and requires:
- OpenHarmony build environment (HB, GN, Ninja)
- OpenHarmony SDK
- Linux build environment (Ubuntu 18.04+ recommended)

### Build Commands

```bash
# Build all bundle framework targets for a specific product
./build.sh --product-name rk3568 --build-target bundle_framework

# Or for other common products
./build.sh --product-name ohos-sdk --build-target bundle_framework
./build.sh --product-name rk3568 --build-target bms_target

# Build only the service layer
./build.sh --product-name rk3568 --build-target services/bundlemgr:bms_target

# Build with specific feature enabled
./build.sh --product-name rk3568 --build-target bundle_framework --gn-args bundle_framework_free_install=true
```

### Common Build Issues

- Ensure `hb` tool is properly installed and in PATH
- Product name must match available products in OpenHarmony vendor tree
- Feature flags can be toggled via `--gn-args` parameter

## Architecture

### Directory Structure

```
bundlemanager_bundle_framework/
├── interfaces/                      # Interface layer
│   ├── inner_api/                   # Internal APIs (for other subsystems)
│   └── kits/                        # Application development interfaces (supports C/C++, JS, Cangjie, ANI)
├── services/                        # Service implementations
│   └── bundlemgr/                   # Bundle manager service
│       ├── include/                 # Header files (organized same as src/)
│       ├── src/                     # Source code
│       │   ├── aging/               # Bundle aging management (resource cleanup)
│       │   ├── aot/                 # AOT (Ahead-Of-Time) compilation management
│       │   ├── app_control/         # Application control and app jump interception
│       │   ├── app_provision_info/  # App provisioning profile management
│       │   ├── app_service_fwk/     # Application service framework installation
│       │   ├── bms_extension/       # BMS extension client
│       │   ├── bundle_backup/       # Backup and restore functionality
│       │   ├── bundle_resource/     # Bundle resource management
│       │   ├── bundlemgr_ext/       # BundleManager extension
│       │   ├── clone/               # Application clone support
│       │   ├── common/              # Common utilities and helper classes
│       │   ├── data/                # Data processing
│       │   ├── default_app/         # Default application management
│       │   ├── distributed_manager/ # Distributed bundle management
│       │   ├── driver/              # Driver installation support
│       │   ├── exception/           # Exception handling
│       │   ├── extend_resource/     # Extended resource management
│       │   ├── first_install_data_mgr/ # First installation data management
│       │   ├── free_install/        # Free installation (on-demand) capability
│       │   ├── idle_condition_mgr/  # Idle condition management
│       │   ├── installd/            # Installd client (privileged process)
│       │   ├── ipc/                 # IPC communication
│       │   ├── navigation/          # Navigation related
│       │   ├── on_demand_install/   # On-demand installation
│       │   ├── overlay/             # Overlay installation support
│       │   ├── plugin/              # Plugin support
│       │   ├── quick_fix/           # Quick fix (patch) management
│       │   ├── rdb/                 # Relational database wrapper
│       │   ├── rpcid_decode/        # RPC ID decoding
│       │   ├── sandbox_app/         # Sandbox application support
│       │   ├── shared/              # Shared bundle management
│       │   ├── uninstall_data_mgr/  # Uninstallation data management
│       │   ├── user_auth/           # User authentication
│       │   ├── utd/                 # Unified Type Descriptor
│       │   └── verify/              # Verification functionality
│       └── test/                    # Service layer unit tests
├── test/                            # System/integration level tests
└── etc/                             # Configuration files
```

### Key Components

Core components and functional subsystems of the bundle management framework (located in `services/bundlemgr/src/`):

#### Core Service Classes

- **bundle_mgr_service.cpp**: BundleMgrService implementation (SA 401), main system ability service that coordinates all bundle management operations
- **bundle_data_mgr.cpp**: BundleDataMgr implementation, central data manager for storing and querying bundle/component information
- **bundle_installer.cpp**: BundleInstaller implementation, handles installation, update, and uninstallation logic
- **bundle_mgr_host_impl.cpp**: BundleMgrHostImpl implementation, provides IPC host for IBundleMgr interface

#### Functional Module Categories

**Installation and Uninstallation**
- **base_bundle_installer.cpp**: Base installer implementation
- **bundle_install_checker.cpp**: Installation checker
- **bundle_parser.cpp**: Bundle parser
- **installd/**: Installd client, communicates with InstalldService (SA 511) via IPC, performs privileged file/directory operations

**Data and Resource Management**
- **data/**: Data processing modules
- **rdb/**: Relational database wrapper
- **bundle_resource/**: Bundle resource management
- **extend_resource/**: Extended resource management
- **bundle_backup/**: Backup and restore functionality

**Permissions and Security**
- **verify/**: Verification functionality (code signing, integrity checks, etc.)
- **bundle_permission_mgr.cpp**: Bundle permission management
- **user_auth/**: User authentication

**Advanced Features**
- **free_install/**: Free installation (on-demand) capability
- **on_demand_install/**: On-demand installation
- **overlay/**: Overlay installation support
- **quick_fix/**: Quick fix (patch) management
- **clone/**: Application clone support
- **sandbox_app/**: Sandbox application support
- **shared/**: Shared bundle management
- **aot/**: AOT (Ahead-Of-Time) compilation management

**Application Control**
- **app_control/**: Application control and app jump interception
- **default_app/**: Default application management
- **app_service_fwk/**: Application service framework installation

**Distributed and Backup**
- **distributed_manager/**: Distributed bundle management
- **first_install_data_mgr/**: First installation data management
- **uninstall_data_mgr/**: Uninstallation data management

**System Functions**
- **aging/**: Bundle aging management for resource cleanup
- **app_provision_info/**: App provisioning profile management
- **bms_extension/**: BMS extension client
- **bundlemgr_ext/**: BundleManager extension
- **driver/**: Driver installation support
- **exception/**: Exception handling
- **idle_condition_mgr/**: Idle condition management
- **navigation/**: Navigation related
- **plugin/**: Plugin support
- **rpcid_decode/**: RPC ID decoding
- **utd/**: Unified Type Descriptor

**Communication and Infrastructure**
- **ipc/**: IPC communication
- **common/**: Common utilities and helper classes

### Process Architecture

The bundle management framework adopts a **multi-process architecture**, separating operations with different privilege levels into independent processes. Bundle management calls to the installd module require IPC:

#### BundleMgrService (SA 401)
- **Process**: Foundation process
- **Function**: Provides core APIs for application bundle management (installation, uninstallation, query, etc.)
- **Dependent Services**:
  - Common event service (for system events)
  - Bundle proxy service
  - EL5 file encryption key service
  - InstalldService (SA 511)

#### InstalldService (SA 511)
- **Process**: Installs process (independent privileged process)
- **Function**: Executes file system operations that require elevated privileges
- **Configuration**: See `sa_profile/511.json`
  - Process name: `installs`
  - Library file: `libinstalls.z.so`
  - Start phase: `CoreStartPhase`
  - On-demand unload: Automatically unloads after 180 seconds of inactivity

## Build System

This project uses **GN (Generate Ninja)** as the build system.

### Key Build Files

- Root build: `BUILD.gn`
- Service build: `services/bundlemgr/BUILD.gn`
- Configuration: `appexecfwk.gni`, `services/bundlemgr/appexecfwk_bundlemgr.gni`

### Build Targets

Main build target:
```bash
# Build all bundle framework targets
./build.sh --product-name <product> --build-target bundle_framework
```

### Build Configuration

Feature switches (defined in `appexecfwk.gni`):
- `bundle_framework_free_install`: Enable free installation capability
- `bundle_framework_default_app`: Enable default application management
- `bundle_framework_quick_fix`: Enable quick fix support
- `bundle_framework_overlay_install`: Enable overlay installation
- `bundle_framework_sandbox_app`: Enable sandbox application support
- `bundle_framework_graphics`: Enable graphics-related bundle management features
- `bundle_framework_launcher`: Enable launcher service capabilities
- `bundle_framework_form_dimension_2_3`: Enable form dimension 2.3 support
- `bundle_framework_form_dimension_3_3`: Enable form dimension 3.3 support

## Development Patterns

### Logging

**Location**: `common/log/` (see `common/log/README.md` for details)

**Usage**:
```cpp
// Include header file
#include "app_log_wrapper.h"

// Define in GN file
defines = [
    "APP_LOG_TAG = \"BMS\"",
    "LOG_DOMAIN = 0xD001120",
]

// Use logging macros
APP_LOGD("Debug: %{public}d", 123);                      // Debug
APP_LOGI("Info: %{public}s", "string");                  // Info
APP_LOGW("Warning");                                      // Warning
APP_LOGE("Error: %{private}s", "sensitive information"); // Error
```

### Data Storage

**Technology**: Uses RDB (Relational Database) for persistent storage

**Key Files**:
- Interface: `services/bundlemgr/include/bundle_data_storage_interface.h`
- Implementation: `services/bundlemgr/src/rdb/`

### Error Handling

**Error Code Definitions**: `interfaces/kits/native/inner_api/appexecfwk_errors.h`
- Categorized by module: general, installation, database, code signing, quick fix, overlay installation, etc.

**Error Checking Macros**: `services/bundlemgr/src/common/common_fun_ani.h`
- Null pointer checking macros like RETURN_IF_NULL, RETURN_FALSE_IF_NULL, etc.

**Handling Patterns**: Check-and-return, error code mapping (RDB_ERR_MAP, CODE_SIGNATURE_ERR_MAP), exception protection (JSON, dynamic library loading), retry mechanisms

## Testing

### Test Structure

- `test/unittest/`: Unit tests for individual components
- `test/moduletest/`: Module integration tests
- `test/systemtest/`: System-level end-to-end tests
- `test/benchmarktest/`: Performance benchmark tests
- `test/fuzztest/`: Fuzzing tests
- `test/sceneProject/`: Test HAP files and test applications

### Test Resources

- `test/resource/bmssystemtestability/`: Test Ability source code
- `test/resource/bundlemgrservice/`: Bundle manager service test resources

### Running Tests

```bash
# Build all test targets
./build.sh --product-name rk3568 --build-target test_target

# Run specific test types
./build.sh --product-name rk3568 --build-target test/unittest
./build.sh --product-name rk3568 --build-target test/moduletest
./build.sh --product-name rk3568 --build-target test/systemtest
./build.sh --product-name rk3568 --build-target test/benchmarktest
./build.sh --product-name rk3568 --build-target test/fuzztest

# Run individual test component
./build.sh --product-name rk3568 --build-target services/bundlemgr/test:unittest
```

### Test Organization

Tests are organized by the component they test:
- **Unit tests**: Test individual classes and functions in isolation
- **Module tests**: Test integration between related components
- **System tests**: End-to-end testing of the full bundle management workflow
- **Benchmark tests**: Performance testing for critical paths
- **Fuzz tests**: Security and robustness testing with malformed inputs

## Important Concepts

- **Bundle**: Application package (HAP file), containing code, resources, and configuration
- **HAP**: Harmony Ability Package - OpenHarmony application package format
- **Module**: HAP file containing one or more Abilities
- **Ability**: Application component representing functionality
- **Extension**: Special Ability type (data, cards, etc.)
- **InnerBundleInfo**: Internal representation of bundle information, containing rich metadata
- **ApplicationInfo**: Application-level information (package name, version, permissions, etc.)
- **AbilityInfo**: Component-level information (type, launch mode, permissions, etc.)

## Key Dependencies

This component depends on many OpenHarmony subsystems (see `bundle.json` for complete list):
- `ability_runtime`: Ability framework
- `samgr`: System ability manager
- `ipc`: IPC framework
- `storage_service`: File storage
- `access_token`: Permission management
- `resource_manager`: Resource management
- `appverify`: Application verification
- `hitrace`, `hisysevent`, `hilog`: DFX capabilities

## Debugging

### Log Locations

Bundle manager logs are routed through HiLog (OpenHarmony's logging system):

- **Service logs**: BundleMgrService (SA 401) outputs to system log with domain `0xD001120`
- **Installd logs**: InstalldService (SA 511) outputs with its own log domain
- **Log viewing**: Use `hdc shell hilog -T BMS` to filter bundle manager logs

### Dynamic Log Control

```cpp
// In code, dynamically adjust log level
AppLogWrapper::SetLogLevel(AppLogLevel::DEBUG);  // Show all logs
AppLogWrapper::SetLogLevel(AppLogLevel::ERROR);  // Show only errors
```

### HiSysEvent Events

Bundle manager reports events via HiSysEvent (see `hisysevent.yaml` for schema):

Common event domains:
- `BMS_INSTALL`: Installation/uninstallation events
- `BMS_CODE_SIGNATURE`: Code signing verification events
- `BMS_QUICK_FIX`: Quick fix patch events
- `BMS_OVERLAY`: Overlay installation events

### Viewing Events

```bash
# View bundle manager events
hdc shell hidumper -s 1201 -a "-e BMS"

# Query specific events
hdc shell hisysevent -q -d BMS_INSTALL -t 100
```

### Common Debugging Scenarios

**Installation failures:**
1. Check InstalldService status: `hdc shell hidumper -s 511`
2. Verify signature verification in logs
3. Check disk space and permissions

**Permission issues:**
1. Verify access token grants in logs
2. Check `bundle_permission_mgr.cpp` flow
3. Review provisioning profile parsing

**IPC communication issues:**
1. Verify both SA 401 and SA 511 are running: `hdc shell hidumper -s samgr`
2. Check for death recipient callbacks in logs
3. Monitor binder transaction logs

**Database issues:**
1. Check RDB storage initialization in `bundle_data_storage_rdb.cpp`
2. Verify database schema in `services/bundlemgr/src/rdb/`
3. Look for transaction failures in logs

### Gotchas

- **Privilege separation**: File operations must go through InstalldService (SA 511), not directly in BundleMgrService
- **Multi-user support**: Bundle operations are user-scoped; always check userId parameter
- **IPC timeout**: Bundle operations can take time; adjust timeout if installing large HAPs
- **RDB transaction conflicts**: Database operations may fail during concurrent installations
- **Signature verification**: All HAPs must be signed; development signing differs from production
- **Overlay installation**: Overlay bundles have special restrictions on target bundles

## Configuration Files

- `bundle.json`: Component metadata and dependencies
- `sa_profile/401.json`: System ability configuration for BundleMgrService
- `sa_profile/511.json`: System ability configuration for installation service
- `services/bundlemgr/installs.cfg`: Installation configuration
- `hisysevent.yaml`: HiSysEvent event reporting configuration
