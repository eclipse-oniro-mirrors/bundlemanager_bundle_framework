# 日志检查清单

## 选择日志宏

- 当前文件已使用 `APP_LOG*`：优先沿用 `APP_LOG*`。
- 当前文件使用 BMS tag 日志：优先使用 `LOG_NOFUNC_*` 并选择合适 `BMS_TAG_*`。
- 当前文件已有大量 `LOG_*` 且需要位置信息：可以沿用 `LOG_*`，但新增普通日志仍优先考虑 `LOG_NOFUNC_*`。
- Installs 进程：优先考虑 `BMS_TAG_INSTALLD`。
- Installer 安装、卸载、缓存流程：优先考虑 `BMS_TAG_INSTALLER`。
- 查询、proxy、bundle info 获取：优先考虑 `BMS_TAG_QUERY`。
- 无明确分类：使用当前文件已有风格或 `BMS_TAG_DEFAULT`。

## 选择日志级别

- `D`：调试细节、分支路径、非关键中间状态。
- `I`：关键状态变化、服务启动停止、重要操作开始结束。
- `W`：可恢复异常、兼容分支、非致命异常状态。
- `E`：失败路径、返回错误码前、IPC/RDB/文件操作失败。
- `F`：极少使用，仅用于严重不可恢复问题。

## public/private 标注

优先 public：

- 错误码、状态码、枚举值。
- 布尔值、计数、大小、进度。
- 非敏感的固定 tag 或模块名。

倾向 private：

- access token、caller token、证书、签名、profile 原文。
- 用户输入、应用私有数据、账号/设备相关信息。
- 完整文件路径、安装包路径、沙箱路径。
- 可能暴露业务隐私的 bundle/module/ability 信息。

不确定时使用 `%{private}`。

## 格式要求

- 使用 `%{public}s`、`%{private}s`、`%{public}d` 等 HiLog 格式。
- `std::string` 使用 `.c_str()`。
- `size_t` 使用合适格式，例如 `%{public}zu`。
- 百分号文本写成 `%%`。
- 日志语句应能说明失败点，例如 `write bundleName failed` 比 `failed` 更好。

## NOFUNC 检查

- `APP_LOGI_NOFUNC/W_NOFUNC/E_NOFUNC` 和 `LOG_NOFUNC_*` 不会自动附加文件名、函数名、行号。
- BMS tag 日志优先使用 `LOG_NOFUNC_*`。
- begin/end、统计类、固定格式日志、普通流程日志、状态日志、错误码日志都可以使用 `LOG_NOFUNC_*`。
- 复杂失败路径、难以定位的权限拒绝、IPC/RDB/文件操作失败，可以使用带位置信息的 `LOG_*`。
- `APP_LOG*` 模块优先沿用当前文件风格，不要为了 NOFUNC 改动无关日志体系。

## 反模式

- 普通 `%s/%d` 替代 `%{public}s/%{public}d`。
- 打印 token、证书、profile、完整路径等敏感数据为 public。
- 高风险失败只打印 `failed`，没有错误码或失败点。
- 在多层调用中重复打印同一失败。
- 在高频循环里新增大量 `INFO` 或 `ERROR`。
- 在 Installs 相关代码中使用不合适的 tag。

## HiSysEvent

如果日志表示安装、卸载、签名校验、quick fix、overlay 等关键系统事件，检查是否已有 HiSysEvent 上报逻辑或 schema：

- `hisysevent.yaml`
- `bundle_hisysevent.yaml`

日志用于排查；HiSysEvent 用于结构化事件上报。不要用普通日志替代已有事件上报。
