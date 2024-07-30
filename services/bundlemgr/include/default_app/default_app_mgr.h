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

#ifndef FOUNDATION_DEFAULT_APPLICATION_FRAMEWORK_DEFAULT_APP_MGR
#define FOUNDATION_DEFAULT_APPLICATION_FRAMEWORK_DEFAULT_APP_MGR

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
    ErrCode GetDefaultApplication(int32_t userId, const std::string& type, BundleInfo& bundleInfo) const;
    ErrCode SetDefaultApplication(int32_t userId, const std::string& type, const Element& element) const;
    ErrCode ResetDefaultApplication(int32_t userId, const std::string& type) const;
    void HandleUninstallBundle(int32_t userId, const std::string& bundleName) const;
    void HandleCreateUser(int32_t userId) const;
    void HandleRemoveUser(int32_t userId) const;
private:
    DefaultAppMgr();
    ~DefaultAppMgr();
    DISALLOW_COPY_AND_MOVE(DefaultAppMgr);
    void Init();
    ErrCode GetBundleInfoByAppType(int32_t userId, const std::string& type, BundleInfo& bundleInfo) const;
    ErrCode GetBundleInfoByFileType(int32_t userId, const std::string& type, BundleInfo& bundleInfo) const;
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
    bool IsImageSkillsValid(const std::vector<Skill>& skills) const;
    bool IsAudioSkillsValid(const std::vector<Skill>& skills) const;
    bool IsVideoSkillsValid(const std::vector<Skill>& skills) const;
    bool IsPdfSkillsValid(const std::vector<Skill>& skills) const;
    bool IsWordSkillsValid(const std::vector<Skill>& skills) const;
    bool IsExcelSkillsValid(const std::vector<Skill>& skills) const;
    bool IsPptSkillsValid(const std::vector<Skill>& skills) const;
    
    std::shared_ptr<IDefaultAppDb> defaultAppDb_;
    static std::set<std::string> supportAppTypes;
};
}
}
#endif
