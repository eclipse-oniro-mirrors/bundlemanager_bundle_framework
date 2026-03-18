/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include <cstring>

#include "config_policy_utils.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
const char* APPLIST_WHITELIST_DIR = "/etc/user_center/";
IConfigPolicyUtils *g_instance = nullptr;
} // namespace

IConfigPolicyUtils::IConfigPolicyUtils()
{
    g_instance = this;
}

extern "C" char* GetOneCfgFile(const char *pathSuffix, char *buf, unsigned int bufLength)
{
    return g_instance->GetOneCfgFile(pathSuffix, buf, bufLength);
}

extern "C" CfgFiles *GetCfgFiles(const char *pathSuffix)
{
    return g_instance->GetCfgFiles(pathSuffix);
}

extern "C" void FreeCfgFiles(CfgFiles *res)
{
    g_instance->FreeCfgFiles(res);
}

extern "C" CfgDir *GetCfgDirList()
{
    return g_instance->GetCfgDirList();
}

extern "C" void FreeCfgDirList(CfgDir *res)
{
    g_instance->FreeCfgDirList(res);
}

char * ConfigPolicyUtilsMock::GetOneCfgFile(const char *pathSuffix, char *buf, unsigned int bufLength)
{
    size_t prefixLen = strlen(APPLIST_WHITELIST_DIR);
    if (strncmp(pathSuffix, APPLIST_WHITELIST_DIR, prefixLen) == 0) {
        return whiteListConfigPath;
    } else {
        return displayManagerConfigPath;
    }
}
} // namespace AppExecFwk
} // namespace OHOS