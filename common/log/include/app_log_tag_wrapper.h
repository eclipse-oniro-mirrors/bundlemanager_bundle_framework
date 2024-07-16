/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef OHOS_APPEXECFWK_HILOG_TAG_WRAPPER_H
#define OHOS_APPEXECFWK_HILOG_TAG_WRAPPER_H

#include <string>

#include "hilog/log.h"

#ifndef BMS_TAG_DEFAULT
#define BMS_TAG_DEFAULT std::make_pair(0xD001120, "BMS")
#endif

#ifndef BMS_TAG_INSTALLER
#define BMS_TAG_INSTALLER std::make_pair(0xD001101, "BMSInstaller")
#endif

#ifndef BMS_TAG_QUERY
#define BMS_TAG_QUERY std::make_pair(0xD001121, "BMSQuery")
#endif

#ifndef BMS_TAG_INSTALLD
#define BMS_TAG_INSTALLD std::make_pair(0xD001122, "BMSInstalld")
#endif

#define BMS_DOMAIN_ID 0xD001120
#define BMS_DOMAIN_ID_QUERY 0xD001121
#define BMS_DOMAIN_ID_INSTALLD 0xD001122

#define TAG_JOIN(domain, funcTag, extTag) std::make_pair(domain, "BMS" funcTag extTag)

#define BMS_NAPI "Napi"
#define BMS_PROXY "Proxy"
#define BMS_HOST "Host"
#define BMS_IMPL "Impl"
#define BMS_MGR "Mgr"
#define BMS_RDB "RDB"

#define TAG_DISPOSED_RULE_BASE TAG_JOIN(BMS_DOMAIN_ID, "DisposedRuleBase", "")
#define TAG_SET_DISPOSED_RULE(tag) TAG_JOIN(BMS_DOMAIN_ID, "SetDisposedRule", tag)

#ifndef APPEXECFWK_FUNC_FMT
#define APPEXECFWK_FUNC_FMT "%{public}s:%{public}s:%{public}d "
#endif

#ifndef APPEXECFWK_FILE_NAME
#define APPEXECFWK_FILE_NAME (__builtin_strrchr(__FILE__, '/') ? __builtin_strrchr(__FILE__, '/') + 1 : __FILE__)
#endif

#ifndef APPEXECFWK_FUNC_INFO
#define APPEXECFWK_FUNC_INFO APPEXECFWK_FILE_NAME, __FUNCTION__, __LINE__
#endif

#define APPEXECFWK_PRINT_LOG(level, label, fmt, ...)                                    \
        ((void)HILOG_IMPL(LOG_CORE, level, label.first,                                 \
        label.second, APPEXECFWK_FUNC_FMT fmt, APPEXECFWK_FUNC_INFO, ##__VA_ARGS__))

#define LOG_D(label, fmt, ...) APPEXECFWK_PRINT_LOG(LOG_DEBUG, label, fmt, ##__VA_ARGS__)
#define LOG_I(label, fmt, ...) APPEXECFWK_PRINT_LOG(LOG_INFO,  label, fmt, ##__VA_ARGS__)
#define LOG_W(label, fmt, ...) APPEXECFWK_PRINT_LOG(LOG_WARN,  label, fmt, ##__VA_ARGS__)
#define LOG_E(label, fmt, ...) APPEXECFWK_PRINT_LOG(LOG_ERROR, label, fmt, ##__VA_ARGS__)
#define LOG_F(label, fmt, ...) APPEXECFWK_PRINT_LOG(LOG_FATAL, label, fmt, ##__VA_ARGS__)

#endif  // OHOS_APPEXECFWK_HILOG_TAG_WRAPPER_H
