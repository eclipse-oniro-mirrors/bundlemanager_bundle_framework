# BMS 日志地图

## 核心文件

- 使用说明：`common/log/README.md`
- APP_LOG 宏：`common/log/include/app_log_wrapper.h`
- BMS tag 宏：`common/log/include/app_log_tag_wrapper.h`
- Log wrapper 实现：`common/log/src/app_log_wrapper.cpp`
- Common GN：`common/BUILD.gn`
- HiSysEvent schema：`hisysevent.yaml`, `bundle_hisysevent.yaml`

## APP_LOG 宏

头文件：

```cpp
#include "app_log_wrapper.h"
```

常用宏：

```cpp
APP_LOGD(fmt, ...)
APP_LOGI(fmt, ...)
APP_LOGW(fmt, ...)
APP_LOGE(fmt, ...)
APP_LOGF(fmt, ...)
```

这些宏会自动输出文件名、函数名和行号。

无函数位置信息版本：

```cpp
APP_LOGI_NOFUNC(fmt, ...)
APP_LOGW_NOFUNC(fmt, ...)
APP_LOGE_NOFUNC(fmt, ...)
```

仅在需要固定、简短或不带位置前缀的日志时使用。

## LOG_* 宏

头文件：

```cpp
#include "app_log_tag_wrapper.h"
```

常用宏：

```cpp
LOG_D(label, fmt, ...)
LOG_I(label, fmt, ...)
LOG_W(label, fmt, ...)
LOG_E(label, fmt, ...)
LOG_F(label, fmt, ...)
```

这些宏通过 `BMS_TAG_*` 选择 domain/tag，并会自动输出文件名、函数名和行号。仅在需要位置上下文定位复杂问题时优先使用。

无函数位置信息版本：

```cpp
LOG_NOFUNC_D(label, fmt, ...)
LOG_NOFUNC_I(label, fmt, ...)
LOG_NOFUNC_W(label, fmt, ...)
LOG_NOFUNC_E(label, fmt, ...)
LOG_NOFUNC_F(label, fmt, ...)
```

`LOG_NOFUNC_*` 和 `LOG_*` 使用相同 label，但不会自动输出文件名、函数名和行号。BMS tag 日志默认优先使用这组宏。

## LOG_NOFUNC 使用边界

默认优先使用 `LOG_NOFUNC_*`：

- 成对 begin/end 日志，例如事件回调开始和结束。
- 统计类、固定格式日志。
- 普通流程、状态、错误码、参数检查和可通过日志文本定位的失败点。
- 日志内容本身已经足够定位，或额外位置前缀会干扰阅读和解析。

只有在失败点难以通过日志文本定位，或者相邻代码已统一使用带位置日志时，才使用 `LOG_*`。`APP_LOG*` 模块沿用既有风格；不要为了使用 `LOG_NOFUNC_*` 强行替换已有 `APP_LOG*`。

仓库中可参考：

```cpp
LOG_NOFUNC_I(BMS_TAG_DEFAULT, "eventBack begin");
LOG_NOFUNC_I(BMS_TAG_DEFAULT, "eventBack end");
LOG_NOFUNC_D(BMS_TAG_INSTALLER, "BundleCache stat: ...");
```

## BMS Tags

定义在 `common/log/include/app_log_tag_wrapper.h`：

| Label | Domain | Tag | 常见用途 |
| --- | --- | --- | --- |
| `BMS_TAG_DEFAULT` | `0xD001120` | `BMS` | 默认 BMS 日志 |
| `BMS_TAG_INSTALLER` | `0xD001121` | `BMSInstaller` | 安装、卸载、缓存、installer 流程 |
| `BMS_TAG_QUERY` | `0xD001121` | `BMSQuery` | 查询、proxy、bundle info 读取 |
| `BMS_TAG_INSTALLD` | `0xD001122` | `BMSInstalld` | Installs 进程和特权文件操作 |
| `BMS_TAG_COMMON` | `0xD001123` | `BMSCommon` | 公共工具和通用逻辑 |
| `BMS_TAG_EXT` | `0xD0011FC` | `BMSExt` | BundleManager extension |
| `BMS_TAG_AOT` | `0xD0011E0` | `BMSAot` | AOT 相关逻辑 |

## GN 配置

常见依赖：

```gn
deps = [
  "${common_path}/log:appexecfwk_log_source_set",
]
```

常见 defines：

```gn
defines = [
  "APP_LOG_TAG = \"BMS\"",
  "LOG_DOMAIN = 0xD001120",
]
```

系统测试中常见：

```gn
defines = [ "APP_LOG_TAG = \"BundleMgrTool\"" ]
```

如果模块使用 `LOG_*` 和 `BMS_TAG_*`，通常需要能 include `app_log_tag_wrapper.h`。
