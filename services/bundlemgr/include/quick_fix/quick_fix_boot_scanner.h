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

#ifndef FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_QUICK_FIX_BOOT_SCANNER_H
#define FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_QUICK_FIX_BOOT_SCANNER_H

#include <map>
#include <vector>

#include "bundle_data_mgr.h"
#include "quick_fix_data_mgr.h"
#include "quick_fix_state.h"
#include "singleton.h"

namespace OHOS {
namespace AppExecFwk {
class QuickFixBootScanner : public DelayedSingleton<QuickFixBootScanner> {
public:
    QuickFixBootScanner() = default;
    virtual ~QuickFixBootScanner() = default;

    void ProcessQuickFixBootUp();

    void SetQuickFixState(const std::shared_ptr<QuickFixState> &state);

    ErrCode ProcessState() const;

    void RestoreQuickFix();

private:
    void ProcessQuickFixDir(const std::vector<std::string> &fileDir);
    bool ReprocessQuickFix(const std::string &quickFixPath, const std::string &bundleName) const;
    bool GetApplicationInfo(const std::string &bundleName, const std::string &quickFixPath, ApplicationInfo &info);
    bool ProcessWithBundleHasQuickFixInfo(const std::string &bundleName, const std::string &hqfPath,
        int32_t quickFixVersion, int32_t fileVersion);
    void RemoveInvalidDir() const;

    std::shared_ptr<QuickFixState> state_ = nullptr;
    std::shared_ptr<QuickFixDataMgr> quickFixDataMgr_ = nullptr;
    std::shared_ptr<BundleDataMgr> dataMgr_ = nullptr;
    // key is bundleName
    // value is versionCode --- hqfDir
    std::map<std::string, std::pair<int32_t, std::string>> quickFixInfoMap_;
    std::vector<std::string> invalidQuickFixDir_;
};
} // AppExecFwk
} // OHOS

#endif // FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_QUICK_FIX_BOOT_SCANNER_H