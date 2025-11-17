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

#include "bms_fuzztest_util.h"
#include "extend_resource_manager_host_impl.h"
#include "inner_bundle_info.h"

using namespace OHOS::AppExecFwk;
using namespace OHOS::AppExecFwk::BMSFuzzTestUtil;
namespace OHOS {
const std::string FILE_PATH = "/data/service/el1/public/bms/bundle_manager_service/a.hsp";
const std::string DIR_PATH_TWO = "/data/test/test";
const std::string BUNDLE_NAME = "com.ohos.resourcedemo";
void GenerateExtendResourceInfo(FuzzedDataProvider& fdp, ExtendResourceInfo &extendResourceInfo)
{
    extendResourceInfo.iconId = fdp.ConsumeIntegral<uint32_t>();
    extendResourceInfo.moduleName = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    extendResourceInfo.filePath = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
}

bool DoSomethingInterestingWithMyAPI(const uint8_t* data, size_t size)
{
    ExtendResourceManagerHostImpl impl;
    FuzzedDataProvider fdp(data, size);
    std::vector<std::string> filePaths = GenerateStringArray(fdp);
    std::string bundleName = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    impl.AddExtResource(bundleName, filePaths);

    std::vector<ExtendResourceInfo> infos;
    for (size_t i = 0; i < filePaths.size(); ++i) {
        ExtendResourceInfo info;
        GenerateExtendResourceInfo(fdp, info);
        infos.emplace_back(info);
    }
    impl.InnerSaveExtendResourceInfo(bundleName, filePaths, infos);
    infos.clear();
    impl.ParseExtendResourceFile(bundleName, filePaths, infos);
    int32_t userId = GenerateRandomUser(fdp);
    impl.CheckWhetherDynamicIconNeedProcess(bundleName, userId);
    impl.CheckAcrossUserPermission(userId);
    impl.IsNeedUpdateBundleResourceInfo(bundleName, userId);
    std::vector<DynamicIconInfo> dynamicInfos;
    impl.GetDynamicIconInfo(bundleName, dynamicInfos);
    dynamicInfos.clear();
    impl.GetAllDynamicIconInfo(userId, dynamicInfos);
    impl.GetAllDynamicIconInfo(dynamicInfos);
    InnerBundleInfo innerBundleInfo;
    int32_t appIndex = fdp.ConsumeIntegral<int32_t>();
    impl.CheckParamInvalid(innerBundleInfo, userId, appIndex);
    std::string moduleName;
    impl.GetDynamicIcon(bundleName, userId, appIndex, moduleName);
    impl.ResetBundleResourceIcon(bundleName, userId, appIndex);
    impl.DisableDynamicIcon(bundleName, userId, appIndex);
    ExtendResourceInfo extendResourceInfo;
    GenerateExtendResourceInfo(fdp, extendResourceInfo);
    impl.ParseBundleResource(bundleName, extendResourceInfo, userId, appIndex);
    moduleName = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    impl.EnableDynamicIcon(bundleName, moduleName, userId, appIndex);

    infos.emplace_back(extendResourceInfo);
    std::vector<std::string> moduleNames = GenerateStringArray(fdp);
    std::vector<ExtendResourceInfo> extendResourceInfos;
    impl.CheckModuleExist(bundleName, moduleNames, extendResourceInfos);
    impl.InnerRemoveExtendResources(bundleName, moduleNames, infos);
    std::vector<std::string> oldFilePaths;
    oldFilePaths.push_back(FILE_PATH);
    std::vector<std::string> newFilePaths = GenerateStringArray(fdp);
    newFilePaths.push_back(DIR_PATH_TWO);
    impl.CopyToTempDir(BUNDLE_NAME, oldFilePaths, newFilePaths);
    impl.CopyToTempDir(bundleName, oldFilePaths, newFilePaths);
    std::string fileName = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    int32_t fd = 0;
    std::string filePath = "data/test";
    impl.CreateFd(fileName, fd, filePath);
    return true;
}
}

// Fuzzer entry point.
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    // Run your code on data.
    OHOS::DoSomethingInterestingWithMyAPI(data, size);
    return 0;
}