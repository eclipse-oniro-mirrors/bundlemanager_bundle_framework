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
#include "bmsbundleresparser_fuzzer.h"
#include "bundle_resource_parser.h"
#include "bundle_resource_process.h"
#include "bms_fuzztest_util.h"
#include "securec.h"

using namespace OHOS::AppExecFwk;
using namespace OHOS::AppExecFwk::BMSFuzzTestUtil;
namespace OHOS {
const std::string HAP_NOT_EXIST = "not exist";
bool DoSomethingInterestingWithMyAPI(const uint8_t* data, size_t size)
{
    FuzzedDataProvider fdp(data, size);
    std::vector<ResourceInfo> resourceInfos;
    std::string bundleName = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    std::string modudleName = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    int32_t userId = GenerateRandomUser(fdp);
    BundleResourceProcess::GetResourceInfoByBundleName(bundleName, userId, resourceInfos);
    ResourceInfo resourceInfo;
    resourceInfo.bundleName_ = bundleName;
    resourceInfo.moduleName_ = modudleName;
    resourceInfo.label_ = bundleName;
    resourceInfo.labelNeedParse_ = false;
    resourceInfo.iconNeedParse_  = false;
    BundleResourceParser parser;
    parser.ParseResourceInfosNoTheme(userId, resourceInfos);
    parser.ParseIconResourceInfosWithTheme(userId, resourceInfos);
    if (!resourceInfos.empty()) {
        parser.ParseResourceInfo(userId, resourceInfos[0]);
        resourceInfos[0].label_ = "";
        resourceInfos[0].icon_ = "";
        parser.ParseResourceInfos(userId, resourceInfos);
        parser.ParseIconResourceByPath(resourceInfos[0].hapPath_, resourceInfos[0].iconId_, resourceInfo);
        parser.ParseResourceInfosNoTheme(userId, resourceInfos);
        parser.ParseIconResourceInfosWithTheme(userId, resourceInfos);
    }
    int32_t appIndex = 1;
    parser.ParserCloneResourceInfo(appIndex, resourceInfos);
    parser.ParseResourceInfoWithSameHap(userId, resourceInfo);
    std::string label = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    std::string hapPath = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    uint32_t labelId = fdp.ConsumeIntegral<uint32_t>();
    parser.ParseLabelResourceByPath(HAP_NOT_EXIST, 0, label);
    parser.ParseLabelResourceByPath(hapPath, labelId, label);
    parser.ParseLabelResourceByPath("", labelId, label);
    std::shared_ptr<Global::Resource::ResourceManager> resourceManager(Global::Resource::CreateResourceManager());
    parser.ParseResourceInfoByResourceManager(resourceManager, resourceInfo);
    parser.ParseLabelResourceByResourceManager(resourceManager, 0, label);
    parser.ParseIconResourceByResourceManager(resourceManager, resourceInfo);
    nlohmann::json layeredImagedJson = R"(
        {
            "layered" : {
                "background" : "$media:1",
                "foreground" : "$media:2"
            }
        }
    )"_json;
    std::string jsonBuff(layeredImagedJson.dump());
    parser.ParseForegroundAndBackgroundResource(resourceManager, jsonBuff, 0, resourceInfo);
    uint32_t foregroundId = 0;
    uint32_t backgroundId = 0;
    parser.ParseIconIdFromJson(jsonBuff, foregroundId, backgroundId);
    uint32_t iconId = 1;
    int32_t density = 0;
    std::vector<uint8_t> datas;
    parser.GetMediaDataById(resourceManager, iconId, density, datas);
    ResourceInfo newResourceInfo;
    parser.IsNeedToParseResourceInfo(newResourceInfo, resourceInfo);
    std::map<std::string, std::string> labelMap;
    parser.ParseUninstallBundleResource(resourceInfo, labelMap);
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
