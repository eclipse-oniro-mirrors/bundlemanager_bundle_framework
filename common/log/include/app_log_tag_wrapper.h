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

#include <map>

#include "hilog/log.h"

#ifndef APPEXECFWK_FUNC_FMT
#define APPEXECFWK_FUNC_FMT "[%{public}s(%{public}s:%{public}d)]"
#endif

#ifndef APPEXECFWK_FILE_NAME
#define APPEXECFWK_FILE_NAME (__builtin_strrchr(__FILE__, '/') ? __builtin_strrchr(__FILE__, '/') + 1 : __FILE__)
#endif

#ifndef APPEXECFWK_FUNC_INFO
#define APPEXECFWK_FUNC_INFO APPEXECFWK_FILE_NAME, __FUNCTION__, __LINE__
#endif


namespace OHOS::AppExecFwk {
enum class AppExecFwkLogTag : uint32_t {
    DEFAULT = 0xD001100,               // 0XD001100
    INSTALLER,

    START = DEFAULT + 0x10,            // 0xD001110

    QUERY = DEFAULT + 0x20,            // 0xD001120

    MULTI_USER = DEFAULT + 0x80,       // 0xD001180

    APP_CONTROL = DEFAULT + 0x88,      // 0xD001180

    FREE_INSTALL = DEFAULT + 0x90,     // 0xD001190

    DEFAULT_APP = DEFAULT + 0xA0,      // 0xD0011A0

    SECURE = DEFAULT + 0xB0,           // 0xD0011B0

    QUICK_FIX = DEFAULT + 0xC0,        // 0xD0011C0

    INSTALLD = DEFAULT + 0xD0,         // 0xD0011D0

    DBMS = DEFAULT + 0xE0,             // 0xD0011E0

    COMMON = DEFAULT + 0xF0,           // 0xD0011F0
};

const inline std::map<AppExecFwkLogTag, const char*> DOMAIN_MAP = {
    { AppExecFwkLogTag::DEFAULT, "BMS" },
    { AppExecFwkLogTag::INSTALLER, "BMSInstaller" },
    { AppExecFwkLogTag::START, "BMSStart" },
    { AppExecFwkLogTag::QUERY, "BMSQuery" },
    { AppExecFwkLogTag::MULTI_USER, "BMSMultiUser" },
    { AppExecFwkLogTag::APP_CONTROL, "BMSAppControl" },
    { AppExecFwkLogTag::FREE_INSTALL, "BMSFreeInstall"},
    { AppExecFwkLogTag::DEFAULT_APP, "BMSDefaultApp" },
    { AppExecFwkLogTag::SECURE, "BMSSecure" },
    { AppExecFwkLogTag::QUICK_FIX, "BMSQuickFix" },
    { AppExecFwkLogTag::INSTALLD, "BMSInstalld" },
    { AppExecFwkLogTag::DBMS, "DBMS" },
    { AppExecFwkLogTag::COMMON, "BMSCommon" },
};

static inline const char* GetTagInfoFromDomainId(AppExecFwkLogTag tag)
{
    if (DOMAIN_MAP.find(tag) == DOMAIN_MAP.end()) {
        tag = AppExecFwkLogTag::DEFAULT;
    }
    return DOMAIN_MAP.at(tag);
}

} // OHOS::AppExecFwk

using BMSTag = OHOS::AppExecFwk::AppExecFwkLogTag;

#define APPEXECFWK_PRINT_LOG(level, tag, fmt, ...)                                                              \
    do {                                                                                                        \
        BMSTag logTag = tag;                                                                                    \
        ((void)HILOG_IMPL(LOG_CORE, level, static_cast<uint32_t>(logTag),                                       \
        OHOS::AppExecFwk::GetTagInfoFromDomainId(logTag), APPEXECFWK_FUNC_FMT fmt, APPEXECFWK_FUNC_INFO,        \
            ##__VA_ARGS__));                                                                                    \
    } while (0)

#define LOG_D(tag, fmt, ...) APPEXECFWK_PRINT_LOG(LOG_DEBUG, tag, fmt, ##__VA_ARGS__)
#define LOG_I(tag, fmt, ...) APPEXECFWK_PRINT_LOG(LOG_INFO,  tag, fmt, ##__VA_ARGS__)
#define LOG_W(tag, fmt, ...) APPEXECFWK_PRINT_LOG(LOG_WARN,  tag, fmt, ##__VA_ARGS__)
#define LOG_E(tag, fmt, ...) APPEXECFWK_PRINT_LOG(LOG_ERROR, tag, fmt, ##__VA_ARGS__)
#define LOG_F(tag, fmt, ...) APPEXECFWK_PRINT_LOG(LOG_FATAL, tag, fmt, ##__VA_ARGS__)

#endif  // OHOS_APPEXECFWK_HILOG_TAG_WRAPPER_H
