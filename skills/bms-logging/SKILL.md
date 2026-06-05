---
name: bms-logging
description: 用于在 OpenHarmony BundleManager 中新增、修改、审查或排查日志打印。 当需求涉及 APP_LOG、LOG_D/I/W/E/F、LOG_NOFUNC、APP_LOG*_NOFUNC、APP_LOG_TAG、LOG_DOMAIN、BMS_TAG、HiLog、HiSysEvent、日志级别、敏感信息 public/private 标注或日志格式规范时使用。
---

# BMS 日志打印

使用此 skill 处理 BundleManager 的日志新增、调整、审查和排查。

## 工作流程

1. 先判断使用哪套宏：
   - 普通模块、kit、测试中已有 `app_log_wrapper.h`：优先沿用 `APP_LOG*`。
   - 需要 BMS 细分 tag，如 installer/query/installd/common/ext/aot：优先使用 `LOG_NOFUNC_*`。
   - 只有需要自动附加文件名、函数名、行号来定位复杂失败点时，才使用 `LOG_*`。

2. 阅读 `references/logging-map.md`，确认宏、tag、domain 和 GN 配置。

3. 阅读 `references/logging-checklist.md`，检查日志级别、敏感信息和反模式。

4. 使用 `references/search-recipes.md` 查找相邻模块的既有日志风格。

## 基本规则

- BMS tag 日志默认优先使用 `LOG_NOFUNC_*`，让日志内容保持简洁一致。
- 复杂失败路径、难以定位的 IPC/RDB/文件操作问题，可以改用带文件名、函数名、行号的 `LOG_*`。
- 日志格式使用 HiLog 标注，例如 `%{public}d`、`%{private}s`，不要使用普通 `%d`、`%s`。
- 敏感信息倾向 `%{private}`，包括 token、证书、profile、完整路径、用户输入和账号/设备相关信息。
- 错误日志要包含可定位失败点的信息，必要时带错误码。
- 不要在高频循环或热路径中新增大量 `INFO`/`ERROR` 日志。
- 不要在多层调用中对同一失败重复打印 error，避免日志噪音。

## 参考资料

- `references/logging-map.md`：日志宏、tag、domain、GN 配置地图。
- `references/logging-checklist.md`：日志新增和审查清单。
- `references/search-recipes.md`：日志相关搜索命令。
