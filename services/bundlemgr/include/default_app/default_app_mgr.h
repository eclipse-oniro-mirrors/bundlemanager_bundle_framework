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

#include<set>

#include "default_app_db.h"

namespace OHOS {
namespace AppExecFwk {
class DefaultAppMgr {
public:
    DefaultAppMgr();
    ~DefaultAppMgr();
    bool IsDefaultApplication(int32_t userId, const std::string& type);
    bool GetDefaultApplication(int32_t userId, const std::string& type, BundleInfo& bundleInfo);
    bool SetDefaultApplication(int32_t userId, const std::string& type, const Element& element);
    bool ResetDefaultApplication(int32_t userId, const std::string& type);
private:
    bool GetBundleInfo(int32_t userId, const std::string& type, const Element& element, BundleInfo& bundleInfo);
    void InitSupportAppTypes();
    bool IsAppType(const std::string& type);
    bool IsFileType(const std::string& type);
    bool IsMatch(const std::string& type, const std::vector<Skill>& skills);
    bool MatchAppType(const std::string& type, const std::vector<Skill>& skills);
    bool MatchFileType(const std::string& type, const std::vector<Skill>& skills);
    bool IsElementValid(const Element& element);
    bool IsUserIdExist(int32_t userId);
    bool IsBrowserSkillsValid(const std::vector<Skill>& skills);
    bool IsImageSkillsValid(const std::vector<Skill>& skills);
    bool IsAudioSkillsValid(const std::vector<Skill>& skills);
    bool IsVideoSkillsValid(const std::vector<Skill>& skills);
    
    std::shared_ptr<DefaultAppDb> defaultAppDb_;
    std::set<std::string> supportAppTypes;
};
}
}
#endif
