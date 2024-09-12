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
#define private public
#define protected public

#include <cstddef>
#include <cstdint>

#include "app_control_proxy.h"

#include "defaultappmgr_fuzzer.h"
#include "default_app_mgr.h"

using namespace OHOS::AppExecFwk;
namespace OHOS {
    bool DoSomethingInterestingWithMyAPI(const uint8_t *data, size_t size)
    {
        bool ret = false;
        std::string type(reinterpret_cast<const char *>(data), size);

        BundleInfo bundleInfo;
        auto errorCode = DefaultAppMgr::GetInstance().GetDefaultApplication(
            reinterpret_cast<uintptr_t>(data), type, bundleInfo);

        Element element;
        element.bundleName = "";
        ret = DefaultAppMgr::GetInstance().VerifyElementFormat(element);
        errorCode = DefaultAppMgr::GetInstance().SetDefaultApplication(
            reinterpret_cast<uintptr_t>(data), type, element);
        errorCode = DefaultAppMgr::GetInstance().ResetDefaultApplication(reinterpret_cast<uintptr_t>(data), type);
        errorCode = DefaultAppMgr::GetInstance().IsDefaultApplication(reinterpret_cast<uintptr_t>(data), type, ret);
        DefaultAppMgr::GetInstance().HandleCreateUser(reinterpret_cast<uintptr_t>(data));
        DefaultAppMgr::GetInstance().HandleRemoveUser(reinterpret_cast<uintptr_t>(data));
        DefaultAppMgr::GetInstance().HandleUninstallBundle(reinterpret_cast<uintptr_t>(data), type);
        auto normalizedTypeVector = DefaultAppMgr::GetInstance().Normalize(type);
        errorCode = DefaultAppMgr::GetInstance().GetDefaultApplication(
            reinterpret_cast<uintptr_t>(data), type, bundleInfo);
        AAFwk::Want want;
        want.SetElementName("", "");
        ret = DefaultAppMgr::GetInstance().GetDefaultApplication(want,
            reinterpret_cast<uintptr_t>(data), bundleInfo.abilityInfos, bundleInfo.extensionInfos, true);
        DefaultAppMgr::GetInstance().GetBrokerBundleInfo(element, bundleInfo);
        DefaultAppMgr::GetInstance().Init();
        auto isAppType = DefaultAppMgr::GetInstance().IsAppType(type);
        ret = DefaultAppMgr::GetInstance().GetBundleInfo(reinterpret_cast<uintptr_t>(data), type, element, bundleInfo);
        ret = DefaultAppMgr::GetInstance().IsSpecificMimeType(type);
        std::vector<Skill> skills;
        ret = DefaultAppMgr::GetInstance().IsMatch(type, skills);
        ret = DefaultAppMgr::GetInstance().IsUserIdExist(reinterpret_cast<uintptr_t>(data));
        ret = DefaultAppMgr::GetInstance().IsElementEmpty(element);
        ret = DefaultAppMgr::GetInstance().IsElementValid(reinterpret_cast<uintptr_t>(data), type, element);
        ret = DefaultAppMgr::GetInstance().IsEmailWant(want);
        auto str = DefaultAppMgr::GetInstance().GetTypeFromWant(want);
        ret = DefaultAppMgr::GetInstance().IsEmailSkillsValid(skills);
        ret = DefaultAppMgr::GetInstance().IsBrowserSkillsValid(skills);
        ret = DefaultAppMgr::GetInstance().MatchAppType(type, skills);
        ret = DefaultAppMgr::GetInstance().MatchUtd(type, skills);
        ret = DefaultAppMgr::GetInstance().MatchActionAndType(type, type, skills);
        ret = DefaultAppMgr::GetInstance().GetBrokerBundleInfo(element, bundleInfo);
        errorCode = DefaultAppMgr::GetInstance().GetBundleInfoByAppType(reinterpret_cast<uintptr_t>(data),
            type, bundleInfo);
        errorCode = DefaultAppMgr::GetInstance().GetBundleInfoByUtd(reinterpret_cast<uintptr_t>(data),
            type, bundleInfo);
        errorCode = DefaultAppMgr::GetInstance().VerifyPermission(type);
        return true;
    }
}

// Fuzzer entry point.
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    // Run your code on data.
    OHOS::DoSomethingInterestingWithMyAPI(data, size);
    return 0;
}