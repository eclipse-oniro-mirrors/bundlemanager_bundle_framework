# 快速参考

## 常用代码片段

### 搜索 BMS 调用点
```bash
grep -rn "InstalldClient::GetInstance()->" --include="*.cpp" services/bundlemgr/src/
```

### 搜索路径构造来源
```bash
grep -rn "Constants::BUNDLE_CODE_DIR\|ServiceConstants::PATCH_PATH\|ServiceConstants::PATH_SEPARATOR" --include="*.cpp" services/bundlemgr/src/quick_fix/
```

### 搜索 Mock 文件
```bash
grep -rn "InstalldClient::" test/mock/src/
grep -rn "InstalldClient::" test/unittest/*/mock/
grep -rn "InstalldHostImpl::" test/mock/src/
```

### 验证 IPC 序列化一致性
```bash
# 对比 proxy write 和 host read 的顺序和类型
git diff | grep -E "INSTALLD_PARCEL_WRITE|ReadString16|ReadBool|ReadInt32"
```

### 搜索所有需要更新的测试文件
```bash
grep -rn "ExtractQuickFixSoFile\|MethodName" test/
```

## 关键文件路径速查

```
services/bundlemgr/
├── include/
│   ├── bundle_framework_services_ipc_interface_code.h   ← IPC 枚举值
│   ├── bundle_service_constants.h                        ← ServiceConstants
│   ├── installd_client.h                                 ← Client 声明
│   ├── ipc/
│   │   ├── installd_interface.h                          ← IInstalld
│   │   ├── installd_proxy.h                              ← Proxy 声明
│   │   ├── installd_host.h                               ← Host 声明
│   │   └── extract_param.h                               ← ExtractParam struct
│   └── installd/
│       ├── installd_host_impl.h                          ← HostImpl 声明
│       ├── installd_operator.h                           ← Operator 声明
│       └── installd_constants.h                          ← BundleDirScene enum
├── src/
│   ├── installd_client.cpp                               ← Client 实现
│   ├── ipc/
│   │   ├── installd_proxy.cpp                            ← Proxy 实现
│   │   └── installd_host.cpp                             ← Host 实现
│   └── installd/
│       ├── installd_host_impl.cpp                        ← HostImpl 实现
│       └── installd_operator.cpp                         ← Operator 实现
└── test/mock/src/
    ├── installd_client.cpp                               ← Mock Client
    ├── mock_install_client.cpp                           ← Mock Client（no-op）
    └── mock_installd_host_impl.cpp                        ← Mock HostImpl

interfaces/inner_api/appexecfwk_base/include/
└── bundle_constants.h                                    ← Constants
```

## 归档文档模板

```markdown
# {方法名} 下沉到 installd 重构归档

## 概述
## 背景
## 设计决策（方案演进）
## 最终方案（签名、路径逻辑、BMS 简化对比）
## InstalldHostImpl 实现
## 业务逻辑一致性对比
   - BMS 调用链对比
   - ExtractParam 字段对比
   - targetPath 逐场景验证
   - 错误处理对比
   - 调用时序对比
   - 新增校验
   - 总结
## 修改文件清单
## IPC 序列化格式
## 校验覆盖
## 对话关键节点
## 提交信息
```

## IPC 序列化宏

```cpp
// 写入接口令牌（必须第一个）
INSTALLD_PARCEL_WRITE_INTERFACE_TOKEN(parcel, (GetDescriptor()))

// 写入参数
INSTALLD_PARCEL_WRITE(parcel, String16, Str8ToStr16(stringVal))
INSTALLD_PARCEL_WRITE(parcel, Bool, boolVal)
INSTALLD_PARCEL_WRITE(parcel, Int32, int32Val)

// 读取参数
std::string val = Str16ToStr8(data.ReadString16());
bool val = data.ReadBool();
int32_t val = data.ReadInt32();

// 写入返回值
WRITE_PARCEL_ERRCODE_ERRNO_RETURN_FALSE_IF_FAIL(Int32, reply, result);
```

## 常用错误码

| 错误码 | 含义 |
|---|---|
| `ERR_APPEXECFWK_INSTALLD_PERMISSION_DENIED` | 权限校验失败 |
| `ERR_APPEXECFWK_INSTALLD_PARAM_ERROR` | 参数校验失败 |
| `ERR_APPEXECFWK_INSTALLD_EXTRACT_FAILED` | 提取操作失败 |
| `ERR_APPEXECFWK_PARCEL_ERROR` | IPC 序列化错误 |
