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

#ifndef BMS_TAG_DEFAULT
#define BMS_TAG_DEFAULT std::make_pair(0xD001100, "BMS")
#endif

#ifndef BMS_TAG_INSTALLER
#define BMS_TAG_INSTALLER std::make_pair(0xD001101, "BMSInstaller")
#endif

#ifndef BMS_TAG_START
#define BMS_TAG_START std::make_pair(0xD001110, "BMSStart")
#endif

#ifndef BMS_TAG_QUERY
#define BMS_TAG_QUERY std::make_pair(0xD001120, "BMSQuery")
#endif

#ifndef BMS_TAG_QUERY_BUNDLE
#define BMS_TAG_QUERY_BUNDLE std::make_pair(0xD001121, "BMSQueryBundle")
#endif

#ifndef BMS_TAG_QUERY_APPLICATION
#define BMS_TAG_QUERY_APPLICATION std::make_pair(0xD001122, "BMSQueryApplication")
#endif

#ifndef BMS_TAG_QUERY_ABILITY
#define BMS_TAG_QUERY_ABILITY std::make_pair(0xD001123, "BMSQueryAbility")
#endif

#ifndef BMS_TAG_QUERY_EXTENSION
#define BMS_TAG_QUERY_EXTENSION std::make_pair(0xD001124, "BMSQueryExtension")
#endif

#ifndef BMS_TAG_MULTI_USER
#define BMS_TAG_MULTI_USER std::make_pair(0xD001180, "BMSMultiUser")
#endif

#ifndef BMS_TAG_APP_CONTROL
#define BMS_TAG_APP_CONTROL std::make_pair(0xD001188, "BMSAppControl")
#endif

#ifndef BMS_TAG_FREE_INSTALL
#define BMS_TAG_FREE_INSTALL std::make_pair(0xD001190, "BMSFreeInstall")
#endif

#ifndef BMS_TAG_DEFAULT_APP
#define BMS_TAG_DEFAULT_APP std::make_pair(0xD0011A0, "BMSDefaultApp")
#endif

#ifndef BMS_TAG_SECURE
#define BMS_TAG_SECURE std::make_pair(0xD0011B0, "BMSSecure")
#endif

#ifndef BMS_TAG_QUICK_FIX
#define BMS_TAG_QUICK_FIX std::make_pair(0xD0011C0, "BMSQuickFix")
#endif

#ifndef BMS_TAG_INSTALLD
#define BMS_TAG_INSTALLD std::make_pair(0xD0011D0, "BMSInstalld")
#endif

#ifndef BMS_TAG_DBMS
#define BMS_TAG_DBMS std::make_pair(0xD0011E0, "DBMS")
#endif

#ifndef BMS_TAG_COMMON
#define BMS_TAG_COMMON std::make_pair(0xD0011F0, "BMSCommon")
#endif

#ifndef APPEXECFWK_FUNC_FMT
#define APPEXECFWK_FUNC_FMT "[%{public}s(%{public}s:%{public}d)]"
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
