/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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
#include <cstddef>
#include <cstdint>
#include <fuzzer/FuzzedDataProvider.h>

#include "default_app_data.h"
#include "default_app_mgr.h"
#include "default_app_host_impl.h"

#include "bmsdefaultapp_fuzzer.h"
#include "bms_fuzztest_util.h"

using Want = OHOS::AAFwk::Want;
using json = nlohmann::json;
using namespace OHOS::AppExecFwk;
using namespace OHOS::AppExecFwk::BMSFuzzTestUtil;
const int32_t TEST_USERID_100 = 100;
const int32_t INVALID_USERID = -1;
const int32_t START_USERID = 0;
const int32_t INVALID_APPINDEX = -1;
const int32_t TEST_APPINDEX_1 = 1;
namespace OHOS {
bool DoSomethingInterestingWithMyAPI(const uint8_t* data, size_t size)
{
    FuzzedDataProvider fdp(data, size);

    DefaultAppData defaultApp;
    // test ToJson
    nlohmann::json jsonObject1;
    defaultApp.ToJson(jsonObject1);

    // test FromJson g_defaultAppJson not ok
    nlohmann::json jsonObject2;
    jsonObject2["ark_startup_cache"] = json::array();
    defaultApp.FromJson(jsonObject2);

    // test ParseDefaultApplicationConfig, jsonObject3 is empty
    nlohmann::json jsonObject3;
    defaultApp.ParseDefaultApplicationConfig(jsonObject3);

    // test ParseDefaultApplicationConfig, jsonObject3 has no object
    jsonObject3 = {"a", "b"};
    defaultApp.ParseDefaultApplicationConfig(jsonObject3);

    // test IsDefaultApplication
    DefaultAppMgr defaultAppMgr;
    std::string type = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    bool isDefaultApp = false;
    defaultAppMgr.IsDefaultApplication(START_USERID, type, isDefaultApp);
    defaultAppMgr.IsDefaultApplication(TEST_USERID_100, type, isDefaultApp);
    int32_t userId = fdp.ConsumeIntegral<int32_t>();
    defaultAppMgr.IsDefaultApplication(userId, type, isDefaultApp);

    // test IsDefaultApplicationInternal
    defaultAppMgr.IsDefaultApplicationInternal(START_USERID, "IMAGE", isDefaultApp);
    defaultAppMgr.IsDefaultApplicationInternal(TEST_USERID_100, "IMAGE", isDefaultApp);
    defaultAppMgr.IsDefaultApplicationInternal(fdp.ConsumeIntegral<int32_t>(),
        fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH), isDefaultApp);

    // test GetDefaultApplicationInternal
    BundleInfo bundleInfo;
    defaultAppMgr.GetDefaultApplicationInternal(START_USERID, "BROWSER", bundleInfo, fdp.ConsumeBool());
    defaultAppMgr.GetDefaultApplicationInternal(TEST_USERID_100, "BROWSER", bundleInfo, fdp.ConsumeBool());
    defaultAppMgr.GetDefaultApplicationInternal(fdp.ConsumeIntegral<int32_t>(),
        fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH),
        bundleInfo, fdp.ConsumeBool());

    // test SetDefaultApplicationInternal
    Element element;
    defaultAppMgr.SetDefaultApplicationInternal(INVALID_USERID, "IMAGE", element);
    defaultAppMgr.SetDefaultApplicationInternal(START_USERID, "IMAGE", element);
    defaultAppMgr.SetDefaultApplicationInternal(TEST_USERID_100, "IMAGE", element);
    element.abilityName = "com.test";
    element.bundleName = "com.test";
    element.extensionName = "com.test";
    element.moduleName = "com.test";
    defaultAppMgr.SetDefaultApplicationInternal(TEST_USERID_100, "IMAGE", element);
    element.abilityName = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    element.bundleName = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    element.extensionName = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    element.moduleName = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    defaultAppMgr.SetDefaultApplicationInternal(fdp.ConsumeIntegral<int32_t>(),
        fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH), element);

    // test ResetDefaultApplicationInternal
    defaultAppMgr.ResetDefaultApplicationInternal(START_USERID, "IMAGE");
    defaultAppMgr.ResetDefaultApplicationInternal(TEST_USERID_100, "IMAGE");
    defaultAppMgr.ResetDefaultApplicationInternal(INVALID_USERID, "IMAGE");
    defaultAppMgr.ResetDefaultApplicationInternal(fdp.ConsumeIntegral<int32_t>(),
        fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH));

    // test HandleUninstallBundle
    defaultAppMgr.HandleUninstallBundle(INVALID_USERID, "", 0);
    defaultAppMgr.HandleUninstallBundle(TEST_USERID_100, "", 0);
    defaultAppMgr.HandleUninstallBundle(TEST_USERID_100, "com.test", 0);
    defaultAppMgr.HandleUninstallBundle(fdp.ConsumeIntegral<int32_t>(),
        fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH), 0);

    // test IsBrowserWant
    ElementName name;
    std::string bundleName = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    std::string action = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    std::string uri = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    name.SetBundleName(bundleName);
    Want want;
    want.SetElement(name);
    want.SetAction("ohos.want.action.viewData");
    want.SetUri("https://123");
    defaultAppMgr.IsBrowserWant(want);
    want.SetAction("ohos.want");
    defaultAppMgr.IsBrowserWant(want);
    want.SetAction("ohos.want.action.viewData");
    want.SetUri("htt");
    defaultAppMgr.IsBrowserWant(want);
    want.SetAction(action);
    want.SetUri(uri);
    defaultAppMgr.IsBrowserWant(want);

    // test IsEmailWant
    want.SetAction("ohos.want.action.sendToData");
    want.SetUri("mailto");
    defaultAppMgr.IsEmailWant(want);
    want.SetUri("");
    defaultAppMgr.IsEmailWant(want);
    want.SetAction(action);
    want.SetUri(uri);
    defaultAppMgr.IsEmailWant(want);

    // test GetTypeFromWant
    want.SetAction("ohos.want.action.viewData");
    want.SetUri("123");
    want.SetType("");
    defaultAppMgr.GetTypeFromWant(want);
    want.SetType("456");
    defaultAppMgr.GetTypeFromWant(want);
    want.SetUri("://file://content://");
    defaultAppMgr.GetTypeFromWant(want);
    want.SetAction(action);
    want.SetUri(uri);
    defaultAppMgr.GetTypeFromWant(want);

    // test GetDefaultApplication
    want.SetAction("ohos.want.action.viewData");
    want.SetUri("https://123");
    std::vector<AbilityInfo> abilityInfos;
    std::vector<ExtensionAbilityInfo> extensionInfos;
    defaultAppMgr.GetDefaultApplication(want, INVALID_USERID, abilityInfos, extensionInfos, true);
    defaultAppMgr.GetDefaultApplication(want, START_USERID, abilityInfos, extensionInfos, true);
    defaultAppMgr.GetDefaultApplication(want, TEST_USERID_100, abilityInfos, extensionInfos, true);
    want.SetAction(action);
    want.SetUri(uri);
    defaultAppMgr.GetDefaultApplication(want, fdp.ConsumeIntegral<int32_t>(),
        abilityInfos, extensionInfos, fdp.ConsumeBool());

    // test GetBundleInfoByAppType
    std::string appType = "IMAGE";
    BundleInfo bundleInfo2;
    defaultAppMgr.GetBundleInfoByAppType(START_USERID, appType, bundleInfo2, false);
    defaultAppMgr.GetBundleInfoByAppType(TEST_USERID_100, appType, bundleInfo2, false);

    // test GetBundleInfo
    Element element3;
    element3.abilityName = "";
    element3.bundleName = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    element3.extensionName = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    element3.moduleName = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    BundleInfo bundleInfo3;
    defaultAppMgr.GetBundleInfo(START_USERID, appType, element3, bundleInfo3);
    defaultAppMgr.GetBundleInfo(TEST_USERID_100, appType, element3, bundleInfo3);

    // test MatchActionAndType
    std::string action4 = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    std::string type4 = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    std::vector<std::string> actions = {"ohos.want.action.viewData", "ohos.want.action.sendToData"};
    SkillUri uri1;
    std::vector<SkillUri> uris;
    uris.push_back(uri1);
    Skill skill1;
    skill1.actions = actions;
    skill1.uris = uris;
    std::vector<Skill> skills;
    skills.push_back(skill1);
    defaultAppMgr.MatchActionAndType(action4, type4, skills);

    // test IsBrowserSkillsValid
    defaultAppMgr.IsBrowserSkillsValid(skills);

    // test IsEmailSkillsValid
    defaultAppMgr.IsEmailSkillsValid(skills);

    // test IsElementValid
    Element element4;
    element4.abilityName = "";
    element4.bundleName = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    element4.extensionName = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    element4.moduleName = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    std::string type5 = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    defaultAppMgr.IsElementValid(fdp.ConsumeIntegral<int32_t>(), type5, element4);

    // test GetBrokerBundleInfo
    Element element5;
    element5.abilityName = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    element5.bundleName = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    element5.extensionName = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    element5.moduleName = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    BundleInfo bundleInfo4;
    defaultAppMgr.GetBrokerBundleInfo(element5, bundleInfo4);

    // test SendDefaultAppChangeEventIfNeeded
    Element element6;
    element6.abilityName = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    element6.bundleName = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    element6.extensionName = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    element6.moduleName = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    std::vector<std::string> normalizedTypeVec;
    normalizedTypeVec.push_back(fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH));
    std::unordered_map<std::string, std::pair<bool, Element>> originStateMap;
    originStateMap[fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH)] = {false, element6};
    defaultAppMgr.SendDefaultAppChangeEventIfNeeded(fdp.ConsumeIntegral<int32_t>(),
        normalizedTypeVec, originStateMap);

    // test GetDefaultInfo
    std::unordered_map<std::string, std::pair<bool, Element>> defaultInfo;
    defaultAppMgr.GetDefaultInfo(fdp.ConsumeIntegral<int32_t>(), normalizedTypeVec, defaultInfo);

    // test ShouldSendEvent
    defaultAppMgr.ShouldSendEvent(true, element6, true, element6);
    defaultAppMgr.ShouldSendEvent(false, element6, false, element6);
    defaultAppMgr.ShouldSendEvent(fdp.ConsumeBool(), element6, fdp.ConsumeBool(), element6);

    // SendDefaultAppChangeEvent
    std::vector<std::string> typeVec;
    defaultAppMgr.SendDefaultAppChangeEvent(fdp.ConsumeIntegral<int32_t>(), typeVec);
    typeVec.push_back("BROWSER");
    typeVec.push_back("VIDEO");
    typeVec.push_back(fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH));
    defaultAppMgr.SendDefaultAppChangeEvent(fdp.ConsumeIntegral<int32_t>(), typeVec);

    DefaultAppHostImpl defaultAppHostImpl;
    type = "BROWSER";
    BundleInfo bundleInfo5;
    Element element7;
    element7.abilityName = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    element7.bundleName = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    element7.extensionName = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    element7.moduleName = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    Want want2;
    bundleName = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    action = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    uri = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    name.SetBundleName(bundleName);
    want2.SetElement(name);
    want2.SetAction("ohos.want.action.viewData");
    want2.SetUri("https://123");
    want2.SetElementName("", "");
    defaultAppHostImpl.SetDefaultApplication(TEST_USERID_100, type, want2);
    defaultAppHostImpl.SetDefaultApplication(START_USERID, type, want2);

    // test ResetDefaultApplication
    defaultAppHostImpl.ResetDefaultApplication(TEST_USERID_100, type);
    defaultAppHostImpl.ResetDefaultApplication(START_USERID, type);

    // test GetCallerName
    defaultAppHostImpl.GetCallerName();

    // test SetDefaultApplicationForAppClone
    defaultAppHostImpl.SetDefaultApplicationForAppClone(INVALID_USERID, TEST_APPINDEX_1, type, want2);
    defaultAppHostImpl.SetDefaultApplicationForAppClone(TEST_USERID_100, INVALID_APPINDEX, type, want2);
    defaultAppHostImpl.SetDefaultApplicationForAppClone(TEST_USERID_100, TEST_APPINDEX_1, type, want2);

    return true;
}
}

// Fuzzer entry point.
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::DoSomethingInterestingWithMyAPI(data, size);
    return 0;
}