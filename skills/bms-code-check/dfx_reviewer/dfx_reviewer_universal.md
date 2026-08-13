# DFX Code Review Skill (Universal Version)

## Purpose

This skill provides **universal** guidance for reviewing DFX (Diagnostic Facilities) code, focusing on HiSysEvent and HiTrace components. It can be adapted to any codebase with minimal configuration.

**Design Philosophy**:
- ✅ **Language Agnostic**: Works with C++, Rust, Java, etc.
- ✅ **Framework Agnostic**: Applicable to any system using HiSysEvent/HiTrace
- ✅ **Domain Independent**: No hardcoded business logic
- ✅ **Easily Configurable**: Simple template replacement for customization

---

## 🎯 Quick Start for Your Codebase

### Step 1: Define Your Codebase Structure

Replace the placeholder directories with your actual codebase structure:

```yaml
# Template Configuration
codebase:
  name: "Your_Module_Name"  # e.g., "Account Manager", "Network Stack"

  # Service/Server side (where HiSysEvent is allowed)
  server_dirs:
    - "services/{{module_name}}/src"
    - "services/{{module_name}}/include"
    - "foundation/{{module_name}}/"

  # Client side (where HiSysEvent is NOT allowed)
  client_dirs:
    - "frameworks/{{module_name}}/"
    - "interfaces/kits/{{module_name}}/"
    - "interfaces/innerkits/{{module_name}}/"
    - "sdk/{{module_name}}/"

  # DFX adapter location
  dfx_dirs:
    - "dfx/hisysevent_adapter/"
    - "dfx/hitrace_adapter/"
```

### Step 2: Define Your Event Operations

Create your operation name constants following the naming template:

```cpp
// Template: Replace MODULE with your module name
namespace Constants {
    // Operation types
    const char MODULE_OPT_CREATE[] = "create";           // Create operation
    const char MODULE_OPT_DELETE[] = "delete";           // Delete operation
    const char MODULE_OPT_UPDATE[] = "update";           // Update operation
    const char MODULE_OPT_QUERY[] = "query";             // Query operation

    // Scenario prefixes (add as needed)
    const char SCENARIO_BOOT[] = "boot_";                // System boot
    const char SCENARIO_SETTINGS[] = "settings_";        // Settings UI
    const char SCENARIO_API[] = "api_";                  // API call
    const char SCENARIO_MDM[] = "mdm_";                  // MDM management
}
```

### Step 3: Replace Macro Names

Update the macro names to match your codebase:

```cpp
// Template: Replace PREFIX with your module prefix
#define REPORT_PREFIX_FAIL(id, operation, errCode, errMsg) \
    Report_##PREFIX##_Fail(id, operation, errCode, errMsg)
```

---

## Universal DFX Guidelines

### 1. HiSysEvent Adapter Review

#### 🏗️ Architecture Principle: Client-Side Events Prohibited

**🔴 Critical Rule: Client code MUST NOT perform HiSysEvent logging directly**

**Why This Rule Exists**:
1. **Unified Management**: All events logged at service layer for consistency
2. **Avoid Duplication**: Same operation may be called from multiple clients
3. **Permission Control**: HiSysEvent requires system permissions
4. **Data Consistency**: Server ensures accurate and consistent event parameters
5. **Performance**: Reduce cross-process calls to HiSysEvent service
6. **Security**: Prevent malicious apps from abusing event system

**Directory Rules**:

| Code Location | HiSysEvent Allowed | Explanation |
|---------------|-------------------|--------------|
| `services/**/` | ✅ **YES** | Server-side implementation |
| `foundation/**/` | ✅ **YES** | Foundation services |
| `dfx/**/` | ✅ **YES** | DFX adapter implementations |
| `frameworks/**/` | ❌ **NO** | Framework layer / clients |
| `interfaces/kits/**/` | ❌ **NO** | SDK / Kit clients |
| `interfaces/innerkits/**/` | ❌ **NO** | Inner interface clients |
| `sdk/**/` | ❌ **NO** | SDK clients |

**Correct Implementation Pattern**:

```cpp
// ❌ WRONG: Client-side logging
// Location: frameworks/your_module/your_client.cpp
ErrCode YourClient::DoOperation(const Input &input)
{
    ErrCode ret = proxy_->DoOperation(input);
    if (ret != ERR_OK) {
        // WRONG: Client should NOT log events directly
        REPORT_YOUR_MODULE_FAIL(id, "operation", ret, "Failed");
        return ret;
    }
    return ret;
}

// ✅ CORRECT: Client calls server, server logs event
// Location: frameworks/your_module/your_client.cpp
ErrCode YourClient::DoOperation(const Input &input)
{
    // CORRECT: Client only calls server, no event logging
    return proxy_->DoOperation(input);
}

// ✅ CORRECT: Server-side logging
// Location: services/your_module/your_service.cpp
ErrCode YourService::DoOperation(const Input &input)
{
    ErrCode ret = DoOperationInternal(input);
    if (ret != ERR_OK) {
        // CORRECT: Server logs the event
        REPORT_YOUR_MODULE_FAIL(id, MODULE_OPT_OPERATION, ret,
                              "Operation failed");
        return ret;
    }

    // Log success event
    ReportOperationLifeCycle(id, MODULE_OPT_OPERATION);
    return ERR_OK;
}
```

**Exception Cases**:

**Exception Type 1: Low-Level Utilities**

Low-level utilities (file operators, network wrappers, etc.) that are used by both server and client may log events:

```cpp
// Exception: Low-level utility event logging
// Location: common/utils/file_operator.cpp
bool FileOperator::ReadFile(const std::string &path)
{
    // This is a low-level utility used by multiple modules
    // It may log basic operation failures
    if (!FileExists(path)) {
        REPORT_COMMON_FAIL(-1, OPERATION_FILE, ENOENT, "File not found");
        return false;
    }
    return true;
}
```

**Requirements for Low-Level Utilities**:
- ✅ Used by multiple modules (server and client)
- ✅ Only logs basic operations (file, network, etc.)
- ✅ No business semantics
- ✅ Uses generic operation types
- ✅ Approved by architecture team

**Exception Type 2: Client Lifecycle Events**

Client initialization/destroy events (requires architecture approval):

```cpp
// Exception: Client lifecycle event
void YourClient::Init()
{
    // Must have clear comment explaining the exception
    // Exception reason: Need to track client initialization status

    ReportClientLifecycleEvent("YOUR_CLIENT_INITIALIZED");

    // Only for lifecycle, not business operations
}
```

**Exception Requirements**:
1. ✅ Clear comment explaining exception reason
2. ✅ Approved by architecture team
3. ✅ Only for lifecycle tracking (init, connect, destroy)
4. ✅ Business operations must be logged at server
5. ✅ Use dedicated event types

#### Event Naming Conventions

**⚠️ Important: Distinguish Business Scenarios**

When logging HiSysEvent, **you MUST distinguish different business scenarios**. The same operation in different scenarios should use different operation names.

**Why Distinguish Scenarios?**
- Different scenarios have different failure rates, latency, impact
- Need to know the specific trigger scenario for issue diagnosis
- Performance optimization needs to target specific scenarios
- Security audit needs to distinguish operation sources

**Scenario Differentiation Principles**:
1. **Call Source**: Settings, CLI, API, MDM, System Boot, etc.
2. **User Type**: Admin, Regular User, Guest, System Service
3. **Operation Context**: First-time, Recovery, Migration, Batch, etc.
4. **Device State**: Normal boot, Recovery mode, OTA upgrade, etc.

**Scenario Naming Template**:

```cpp
// Format: {SCENARIO_PREFIX}{OPERATION_NAME}
// Examples:

// Boot scenarios
const char OPERATION_BOOT_CREATE[] = "boot_create";              // Create during boot
const char OPERATION_BOOT_ACTIVATE[] = "boot_activate";          // Activate during boot

// Settings scenarios
const char OPERATION_SETTINGS_CREATE[] = "settings_create";      // Create via settings
const char OPERATION_SETTINGS_DELETE[] = "settings_delete";      // Delete via settings

// API scenarios
const char OPERATION_API_CREATE[] = "api_create";                // Create via API
const char OPERATION_API_QUERY[] = "api_query";                  // Query via API

// MDM scenarios
const char OPERATION_MDM_CREATE[] = "mdm_create";                // Create via MDM
const char OPERATION_MDM_ENROLL[] = "mdm_enroll";                // Enroll via MDM

// Recovery scenarios
const char OPERATION_RECOVERY_RESTORE[] = "recovery_restore";    // Restore in recovery mode
const char OPERATION_RECOVERY_MIGRATE[] = "recovery_migrate";    // Migrate in recovery mode
```

**Scenario Suffix Template**:

| Suffix | Meaning | Use Case |
|--------|---------|----------|
| `_local` | Local operation | Operations not requiring network |
| `_network` / `_online` | Network operation | Operations requiring network |
| `_offline` | Offline operation | Operations in offline mode |
| `_background` | Background operation | Non-user-triggered operations |
| `_foreground` | Foreground operation | User-triggered operations |
| `_auto` | Automatic operation | System automatic operations |
| `_manual` | Manual operation | Operations requiring user confirmation |

**Implementation Example**:

```cpp
// ❌ BAD: No scenario distinction
ErrCode CreateResource(const std::string &name)
{
    ErrCode ret = CreateResourceInternal(name);
    if (ret != ERR_OK) {
        REPORT_MODULE_FAIL(id, "create", ret, "Failed");
        return ret;
    }
    ReportResourceLifeCycle(id, "create");
    return ERR_OK;
}

// ✅ GOOD: Distinguish scenarios
ErrCode CreateResource(const std::string &name, CreationScenario scenario)
{
    std::string operationName;

    // Choose operation name based on scenario
    switch (scenario) {
        case CreationScenario::BOOT:
            operationName = OPERATION_BOOT_CREATE;
            break;
        case CreationScenario::SETTINGS:
            operationName = OPERATION_SETTINGS_CREATE;
            break;
        case CreationScenario::MDM:
            operationName = OPERATION_MDM_CREATE;
            break;
        case CreationScenario::API:
            operationName = OPERATION_API_CREATE;
            break;
        default:
            operationName = "create";
            break;
    }

    ErrCode ret = CreateResourceInternal(name);
    if (ret != ERR_OK) {
        REPORT_MODULE_FAIL(id, operationName, ret, "Failed to create resource");
        return ret;
    }

    ReportResourceLifeCycle(id, operationName);
    return ERR_OK;
}
```

#### Error Reporting Best Practices

**Universal Error Reporting Pattern**:

```cpp
// 1. Always include context in error messages
ErrCode YourFunction(const Input &input)
{
    // Validate input
    if (input.IsEmpty()) {
        REPORT_MODULE_FAIL(id, MODULE_OPT_OPERATION,
                          ERR_INVALID_PARAM,
                          "Input is empty");  // Clear context
        return ERR_INVALID_PARAM;
    }

    // Perform operation
    ErrCode ret = DoOperation(input);
    if (ret != ERR_OK) {
        // Include function name, file, line automatically
        REPORT_MODULE_FAIL(id, MODULE_OPT_OPERATION, ret,
                          ASSEMBLE_ERRMSG("Operation failed"));
        return ret;
    }

    return ERR_OK;
}

// 2. Report both success and failure paths
ErrCode CreateResource(const std::string &name)
{
    ErrCode ret = CreateResourceInternal(name);

    if (ret != ERR_OK) {
        // Failure path
        REPORT_MODULE_FAIL(id, MODULE_OPT_CREATE, ret,
                          "Failed to create resource");
        return ret;
    }

    // Success path
    ReportResourceLifeCycle(id, MODULE_OPT_CREATE);
    return ERR_OK;
}

// 3. Use appropriate error codes
ErrCode YourFunction()
{
    ErrCode ret = ExternalCall();
    if (ret != ERR_OK) {
        // Use meaningful error code, not generic ERR_FAILED
        REPORT_MODULE_FAIL(id, MODULE_OPT_OPERATION, ret,
                          "External call failed with specific code");
        return ret;
    }
}
```

#### Data Privacy Protection

**Universal Privacy Rules**:

1. **Never log raw sensitive data**: passwords, tokens, credentials, keys
2. **Anonymize user data**: user IDs, names, email addresses
3. **Log metadata only**: file sizes, token lengths, operation counts
4. **Use anonymization functions**: always when logging user data

**Examples**:

```cpp
// ❌ BAD: Logging sensitive data
LOG_INFO("User password: %{public}s", password.c_str());
LOG_INFO("Auth token: %{public}s", token.c_str());
LOG_INFO("Account name: %{public}s", accountName.c_str());

// ✅ GOOD: Anonymized or metadata only
std::string anonName = AnonymizeData(accountName);
LOG_INFO("Account name: %{public}s", anonName.c_str());

LOG_INFO("Token size: %{public}zu bytes", token.size());
LOG_INFO("Operation completed for user: %{public}d", userId);
```

#### Conditional Compilation

**Always check for HiSysEvent availability**:

```cpp
#ifdef HAS_HISYSEVENT_PART
    // Real HiSysEvent implementation
    void ReportOperationFail(int32_t id, const std::string &operation,
                           int32_t errCode, const std::string &errMsg);
#else
    // Empty stub when HiSysEvent is not available
    inline void ReportOperationFail(...) {}
#endif // HAS_HISYSEVENT_PART
```

---

### 2. HiTrace Adapter Review

#### Trace Scoping

**Universal Rules**:
1. **Always pair** `StartTraceAdapter()` with `FinishTraceAdapter()`
2. **Use RAII** pattern or ensure proper cleanup in error paths
3. **Keep trace sections focused** on meaningful operations
4. **Avoid nested traces** for simple operations

**Best Practice - RAII Guard**:

```cpp
// Language-agnostic RAII pattern concept
class TraceGuard {
public:
    explicit TraceGuard(const std::string &name) : active_(true) {
        StartTraceAdapter(name);
    }
    ~TraceGuard() {
        if (active_) {
            FinishTraceAdapter();
        }
    }
private:
    bool active_;
};

// Usage
ErrCode YourFunction()
{
    TraceGuard guard("YourOperation");

    // Operation code here
    // Automatic cleanup on return
    return DoSomething();
}
```

#### Trace Naming

**Naming Template**:
- Use `{Module}{Operation}` format
- Examples: `DatabaseQuery`, `NetworkRequest`, `FileOperation`
- Avoid: generic names like "trace", "operation", "execute"

#### Performance Thresholds

**Universal performance guidance**:

| Operation Duration | Should Trace? | Priority |
|-------------------|---------------|----------|
| **< 1ms** | No | Skip |
| **1-10ms** | Consider | Critical paths only |
| **10-50ms** | Yes | Normal operations |
| **50-100ms** | Must | Performance sensitive |
| **> 100ms** | Must | High latency operations |

**High-Latency Operation Types**:
- Database operations (queries, inserts, updates)
- File I/O operations (large files, directory ops)
- Network operations (RPC, HTTP, sockets)
- IPC calls (cross-process communication)
- JSON/XML parsing/serialization (large data)
- Encryption/decryption operations
- Data migration/conversion operations

---

## Code Quality Checklist (Universal)

### Architecture Rules
- [ ] **Client-side code does NOT contain HiSysEvent logging**
  - [ ] No `REPORT_*_FAIL` macros in client directories
  - [ ] No direct `HiSysEventWrite` calls in client code
  - [ ] All business events logged at server side
  - [ ] Exceptions approved and documented

### Event Coverage
- [ ] **All error paths** have appropriate HiSysEvent reporting
- [ ] **Success paths** have lifecycle event reporting
- [ ] **Event names** distinguish different scenarios
- [ ] **Error messages** include clear context
- [ ] **Error codes** are meaningful and specific

### Data Privacy
- [ ] **Sensitive data** is anonymized before logging
- [ ] **No raw passwords** or tokens in logs
- [ ] **User data** uses anonymization functions
- [ ] **Only metadata** logged for sensitive operations

### HiTrace Usage
- [ ] **Long operations** (>10ms) have trace spans
- [ ] **Trace operations** are properly paired
- [ ] **Trace names** are descriptive
- [ ] **Performance impact** is minimal

### Code Quality
- [ ] **Conditional compilation** for `HAS_HISYSEVENT_PART`
- [ ] **Memory management** is correct in DFX operations
- [ ] **No performance impact** in hot paths
- [ ] **Naming conventions** followed

---

## Universal Adaptation Guide

### Step-by-Step Adaptation Process

#### Phase 1: Basic Configuration (15 minutes)

1. **Update codebase structure**:
   ```yaml
   # Replace these paths with your actual structure
   server_dirs: ["services/your_module/"]
   client_dirs: ["frameworks/your_module/", "sdk/your_module/"]
   ```

2. **Define your operation constants**:
   ```cpp
   namespace Constants {
       const char YOUR_MODULE_OPT_CREATE[] = "create";
       const char YOUR_MODULE_OPT_DELETE[] = "delete";
       // ... add your operations
   }
   ```

3. **Update macro names**:
   ```cpp
   #define REPORT_YOUR_MODULE_FAIL(id, op, code, msg) \
       ReportYourModuleFail(id, op, code, msg)
   ```

#### Phase 2: Customize Examples (30 minutes)

1. **Replace code examples** with your actual code
2. **Update file paths** to match your structure
3. **Add your specific business scenarios**
4. **Include your error codes and constants**

#### Phase 3: Add Your Specific Rules (30 minutes)

1. **Business-specific scenarios**: What scenarios exist in your domain?
2. **Privacy requirements**: What data is sensitive in your context?
3. **Performance thresholds**: What are your specific latency requirements?
4. **Integration points**: What external systems do you call?

#### Phase 4: Validation (15 minutes)

1. **Run automated checks**: Use provided scripts
2. **Review actual code**: Verify examples match reality
3. **Test with team**: Ensure guidelines are clear
4. **Iterate**: Refine based on feedback

---

## Universal Check Scripts

### Client-Side HiSysEvent Check

```bash
#!/bin/bash
# check_client_hisysevent_universal.sh
# Universal script to check for illegal client-side HiSysEvent logging

CLIENT_DIRS=(
    "frameworks/"
    "interfaces/kits/"
    "interfaces/innerkits/"
    "sdk/"
)

echo "=== Client-Side HiSysEvent Check ==="

VIOLATIONS=0

for dir in "${CLIENT_DIRS[@]}"; do
    if [ ! -d "$dir" ]; then
        continue
    fi

    echo "Checking: $dir"

    # Check for REPORT_*_FAIL macros
    FOUND=$(grep -r "REPORT_.*_FAIL" "$dir" --include="*.cpp" 2>/dev/null | wc -l)
    if [ $FOUND -gt 0 ]; then
        echo "  ❌ Found $FOUND REPORT_*_FAIL calls"
        VIOLATIONS=$((VIOLATIONS + FOUND))
    fi

    # Check for HiSysEventWrite
    FOUND=$(grep -r "HiSysEventWrite" "$dir" --include="*.cpp" 2>/dev/null | wc -l)
    if [ $FOUND -gt 0 ]; then
        echo "  ❌ Found $FOUND HiSysEventWrite calls"
        VIOLATIONS=$((VIOLATIONS + FOUND))
    fi
done

if [ $VIOLATIONS -eq 0 ]; then
    echo "✅ No violations found"
    exit 0
else
    echo "❌ Found $VIOLATIONS violations"
    exit 1
fi
```

---

## Language-Specific Guidelines

### C++ Guidelines

```cpp
// C++ best practices
ErrCode YourFunction()
{
    // Use RAII for trace cleanup
    TraceGuard guard("OperationName");

    // Use smart pointers for memory management
    auto data = std::make_unique<Data>();

    // Check pointers before use
    if (data == nullptr) {
        REPORT_YOUR_MODULE_FAIL(id, "operation",
                              ERR_NULL_PTR, "Data is null");
        return ERR_NULL_PTR;
    }

    return ERR_OK;
}
```

### Rust Guidelines

```rust
// Rust best practices
fn your_function() -> Result<(), Error> {
    // Use RAII-like patterns
    let _guard = TraceGuard::new("OperationName");

    // Use ? operator for error propagation
    let result = do_operation()?;

    // Log events at appropriate level
    if let Err(e) = result {
        report_event("operation", e.code(), "Failed");
        return Err(e);
    }

    Ok(())
}
```

### Java Guidelines

```java
// Java best practices
public ErrCode yourFunction() {
    try (TraceGuard guard = new TraceGuard("OperationName")) {
        // Operation code
        ErrCode ret = doOperation();

        if (ret != ErrCode.OK) {
            reportEvent("operation", ret, "Failed");
            return ret;
        }

        return ErrCode.OK;
    }
}
```

---

## Reference Implementations

### Account Manager (Original)

**Location**: `services/accountmgr/`
**Operations**: Account create, delete, activate
**Scenarios**: Boot, Settings, API, MDM

### Network Stack (Example)

**Location**: `services/network/`
**Operations**: Connect, Disconnect, Send, Receive
**Scenarios**: Boot, User trigger, Auto-reconnect, Background

### Storage Manager (Example)

**Location**: `services/storage/`
**Operations**: Read, Write, Delete, Format
**Scenarios**: Boot, User trigger, System maintenance, Recovery

---

## Quick Reference

### Universal Event Naming Template

```cpp
// Scenario prefixes
const char SCENARIO_BOOT[] = "boot_";
const char SCENARIO_SETTINGS[] = "settings_";
const char SCENARIO_API[] = "api_";
const char SCENARIO_MDM[] = "mdm_";
const char SCENARIO_RECOVERY[] = "recovery_";

// Operation suffixes
const char SUFFIX_LOCAL[] = "_local";
const char SUFFIX_NETWORK[] = "_network";
const char SUFFIX_OFFLINE[] = "_offline";
const char SUFFIX_BACKGROUND[] = "_background";

// Combine: {SCENARIO_PREFIX}{OPERATION_NAME}{SUFFIX}
// Examples: "boot_create_local", "api_query_network"
```

### Common Operation Types

| Operation Type | Generic Name | Example Variants |
|----------------|---------------|------------------|
| Create | `create` | `create`, `add`, `insert` |
| Delete | `delete` | `delete`, `remove`, `drop` |
| Update | `update` | `update`, `modify`, `change` |
| Query | `query` | `query`, `get`, `find`, `search` |
| Connect | `connect` | `connect`, `bind`, `attach` |
| Disconnect | `disconnect` | `disconnect`, `unbind`, `detach` |

---

## Version History

**v3.0 (Universal)**: 2026-03-23
- Universal version for any codebase
- Language-agnostic guidelines
- Framework-independent rules
- Easy adaptation process

**v2.1 (OS Account)**: 2026-03-23
- OS Account specific version
- Client-side prohibition rule

---

## Contributing

To adapt this skill for your codebase:

1. **Copy this file** to your project's `.refdocs/skills/`
2. **Update placeholders** with your specific information
3. **Add your examples** from your actual codebase
4. **Customize checks** for your structure
5. **Share improvements** back to the community

---

## License

This skill template is provided as-is for adaptation and use in any project.

---

**Document Version**: v3.0 (Universal)
**Last Updated**: 2026-03-23
**Maintainability**: High - Designed for easy adaptation
**Portability**: Universal - Works with any codebase
