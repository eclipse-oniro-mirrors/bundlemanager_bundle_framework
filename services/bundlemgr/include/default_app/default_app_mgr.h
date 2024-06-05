/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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

#ifndef FOUNDATION_DEFAULT_APPLICATION_FRAMEWORK_DEFAULT_APP_MGR
#define FOUNDATION_DEFAULT_APPLICATION_FRAMEWORK_DEFAULT_APP_MGR

#include <mutex>
#include <set>

#include "default_app_db_interface.h"
#include "nocopyable.h"

namespace OHOS {
namespace AppExecFwk {
class DefaultAppMgr {
public:
    static DefaultAppMgr& GetInstance();
    static bool VerifyElementFormat(const Element& element);
    ErrCode IsDefaultApplication(int32_t userId, const std::string& type, bool& isDefaultApp) const;
    ErrCode GetDefaultApplication(
        int32_t userId, const std::string& type, BundleInfo& bundleInfo, bool backup = false) const;
    ErrCode SetDefaultApplication(int32_t userId, const std::string& type, const Element& element) const;
    ErrCode ResetDefaultApplication(int32_t userId, const std::string& type) const;
    void HandleUninstallBundle(int32_t userId, const std::string& bundleName) const;
    void HandleCreateUser(int32_t userId) const;
    void HandleRemoveUser(int32_t userId) const;

    bool GetDefaultApplication(const AAFwk::Want& want, const int32_t userId, std::vector<AbilityInfo>& abilityInfos,
        std::vector<ExtensionAbilityInfo>& extensionInfos, bool backup = false) const;
private:
    DefaultAppMgr();
    ~DefaultAppMgr();
    DISALLOW_COPY_AND_MOVE(DefaultAppMgr);
    void Init();
    ErrCode GetBundleInfoByAppType(
        int32_t userId, const std::string& type, BundleInfo& bundleInfo, bool backup = false) const;
    ErrCode GetBundleInfoByFileType(
        int32_t userId, const std::string& type, BundleInfo& bundleInfo, bool backup = false) const;
    bool GetBundleInfo(int32_t userId, const std::string& type, const Element& element, BundleInfo& bundleInfo) const;
    bool IsTypeValid(const std::string& type) const;
    bool IsAppType(const std::string& type) const;
    bool IsFileType(const std::string& type) const;
    bool IsMatch(const std::string& type, const std::vector<Skill>& skills) const;
    bool MatchAppType(const std::string& type, const std::vector<Skill>& skills) const;
    bool MatchFileType(const std::string& type, const std::vector<Skill>& skills) const;
    bool IsElementEmpty(const Element& element) const;
    bool IsElementValid(int32_t userId, const std::string& type, const Element& element) const;
    bool IsUserIdExist(int32_t userId) const;
    ErrCode VerifyUserIdAndType(int32_t userId, const std::string& type) const;
    bool IsBrowserSkillsValid(const std::vector<Skill>& skills) const;
    bool IsEmailSkillsValid(const std::vector<Skill>& skills) const;
    void ConvertTypeBySuffix(std::string& suffix) const;
    bool IsBrowserWant(const AAFwk::Want& want) const;
    bool IsEmailWant(const AAFwk::Want& want) const;
    std::string GetType(const AAFwk::Want& want) const;
    bool MatchActionAndType(const std::string& action, const std::string& type, const std::vector<Skill>& skills) const;
    bool GetBrokerBundleInfo(const Element& element, BundleInfo& bundleInfo) const;
    bool IsSameDefaultApp(const std::vector<BundleInfo>& bundleInfos) const;
    bool IsSameAbilityInfo(const std::vector<BundleInfo>& bundleInfos) const;
    bool IsSameExtensionInfo(const std::vector<BundleInfo>& bundleInfos) const;
    std::vector<std::string> GetMimeTypes(const std::string& utd) const;

    ErrCode IsDefaultApplicationInternal(int32_t userId, const std::string& type, bool& isDefaultApp) const;
    ErrCode GetDefaultApplicationInternal(
        int32_t userId, const std::string& type, BundleInfo& bundleInfo, bool backup = false) const;
    ErrCode SetDefaultApplicationInternal(int32_t userId, const std::string& type, const Element& element) const;
    ErrCode ResetDefaultApplicationInternal(int32_t userId, const std::string& type) const;

    std::shared_ptr<IDefaultAppDb> defaultAppDb_;
    mutable std::mutex mutex_;
};
}
}
#endif
