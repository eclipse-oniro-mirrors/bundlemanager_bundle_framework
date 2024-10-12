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
#include "bundleresparser_fuzzer.h"

#include "bundle_resource_parser.h"
#include "bundle_resource_process.h"
#include "securec.h"

using namespace OHOS::AppExecFwk;
namespace OHOS {
constexpr size_t FOO_MAX_LEN = 1024;
constexpr size_t U32_AT_SIZE = 4;
constexpr uint32_t CODE_MAX = 8;
const int32_t USERID = 100;
const std::string HAP_NOT_EXIST = "not exist";
const std::string MODULE_NAME = "entry";

bool DoSomethingInterestingWithMyAPI(const char* data, size_t size)
{
    std::vector<ResourceInfo> resourceInfos;
    std::string bundleName(data, size);
    BundleResourceProcess::GetResourceInfoByBundleName(bundleName, USERID, resourceInfos);
    ResourceInfo resourceInfo;
    resourceInfo.bundleName_ = bundleName;
    resourceInfo.moduleName_ = MODULE_NAME;
    resourceInfo.label_ = bundleName;
    resourceInfo.labelNeedParse_ = false;
    resourceInfo.iconNeedParse_  = false;
    BundleResourceParser parser;
    if (!resourceInfos.empty()) {
        parser.ParseResourceInfo(USERID, resourceInfos[0]);
        resourceInfos[0].label_ = "";
        resourceInfos[0].icon_ = "";
        parser.ParseResourceInfos(USERID, resourceInfos);
        parser.ParseIconResourceByPath(resourceInfos[0].hapPath_, resourceInfos[0].iconId_, resourceInfo);
    }
    int32_t appIndex = 1;
    parser.ParserCloneResourceInfo(appIndex, resourceInfos);
    parser.ParseResourceInfoWithSameHap(USERID, resourceInfo);
    std::string label(data, size);
    parser.ParseLabelResourceByPath(HAP_NOT_EXIST, 0, label);
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
    parser.ProcessSpecialBundleResource(USERID, resourceInfos);
    return true;
}
}

// Fuzzer entry point.
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    if (data == nullptr) {
        return 0;
    }

    if (size < OHOS::U32_AT_SIZE) {
        return 0;
    }

    /* Validate the length of size */
    if (size > OHOS::FOO_MAX_LEN) {
        return 0;
    }

    char* ch = static_cast<char*>(malloc(size + 1));
    if (ch == nullptr) {
        return 0;
    }

    (void)memset_s(ch, size + 1, 0x00, size + 1);
    if (memcpy_s(ch, size, data, size) != EOK) {
        free(ch);
        ch = nullptr;
        return 0;
    }
    OHOS::DoSomethingInterestingWithMyAPI(ch, size);
    free(ch);
    ch = nullptr;
    return 0;
}