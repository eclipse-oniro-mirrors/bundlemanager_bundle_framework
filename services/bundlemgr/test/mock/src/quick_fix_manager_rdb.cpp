/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include "quick_fix_manager_rdb.h"

#include "app_log_wrapper.h"
#include "appexecfwk_errors.h"
#include "json_serializer.h"

namespace OHOS {
namespace AppExecFwk {
static std::map<std::string, InnerAppQuickFix> INNER_APP_QUICK_FIX_INFOS;

QuickFixManagerRdb::QuickFixManagerRdb()
{}

QuickFixManagerRdb::~QuickFixManagerRdb()
{}

bool QuickFixManagerRdb::QueryAllInnerAppQuickFix(std::map<std::string, InnerAppQuickFix> &innerAppQuickFixes)
{
    APP_LOGI("begin to QueryAllInnerAppQuickFix");
    bool ret = GetAllDataFromDb(innerAppQuickFixes);
    if (!ret) {
        APP_LOGE("GetDataFromDb failed");
        return false;
    }
    return true;
}

bool QuickFixManagerRdb::QueryInnerAppQuickFix(const std::string &bundleName, InnerAppQuickFix &innerAppQuickFix)
{
    APP_LOGI("begin to QueryAppQuickFix");
    bool ret = GetDataFromDb(bundleName, innerAppQuickFix);
    if (!ret) {
        APP_LOGE("GetDataFromDb failed.");
        return false;
    }
    return true;
}

bool QuickFixManagerRdb::SaveInnerAppQuickFix(const InnerAppQuickFix &innerAppQuickFix)
{
    APP_LOGI("begin to SaveInnerAppQuickFix");
    bool ret = SaveDataToDb(innerAppQuickFix);
    if (!ret) {
        APP_LOGE("SaveDataToDb failed.");
        return false;
    }
    return true;
}

bool QuickFixManagerRdb::DeleteInnerAppQuickFix(const std::string &bundleName)
{
    APP_LOGI("begin to DeleteInnerAppQuickFix");
    bool ret = DeleteDataFromDb(bundleName);
    if (!ret) {
        APP_LOGE("DeleteDataFromDb failed.");
        return false;
    }
    return true;
}

bool QuickFixManagerRdb::GetAllDataFromDb(std::map<std::string, InnerAppQuickFix> &innerAppQuickFixes)
{
    innerAppQuickFixes = INNER_APP_QUICK_FIX_INFOS;
    return true;
}

bool QuickFixManagerRdb::GetDataFromDb(const std::string &bundleName, InnerAppQuickFix &innerAppQuickFix)
{
    auto iter = INNER_APP_QUICK_FIX_INFOS.find(bundleName);
    if (iter == INNER_APP_QUICK_FIX_INFOS.end()) {
        return false;
    }
    innerAppQuickFix = iter->second;
    return true;
}

bool QuickFixManagerRdb::SaveDataToDb(const InnerAppQuickFix &innerAppQuickFix)
{
    INNER_APP_QUICK_FIX_INFOS[innerAppQuickFix.GetAppQuickFix().bundleName] = innerAppQuickFix;
    return true;
}

bool QuickFixManagerRdb::DeleteDataFromDb(const std::string &bundleName)
{
    auto ret = INNER_APP_QUICK_FIX_INFOS.erase(bundleName);
    if (ret == 0) {
        return false;
    }
    return true;
}
} // namespace AppExecFwk
} // namespace OHOS
