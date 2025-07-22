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

#include "driver_installer.h"

#include "bmsdriverinstaller_fuzzer.h"
#include "bms_fuzztest_util.h"

using namespace OHOS::AppExecFwk;
using namespace OHOS::AppExecFwk::BMSFuzzTestUtil;
namespace OHOS {
bool DoSomethingInterestingWithMyAPI(const uint8_t* data, size_t size)
{
    DriverInstaller installer;
    FuzzedDataProvider fdp(data, size);

    std::unordered_map<std::string, InnerBundleInfo> newInfos;
    InnerBundleInfo newInfo1;
    newInfo1.baseApplicationInfo_->bundleName = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    newInfo1.SetCurrentModulePackage(fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH));
    newInfos.emplace(newInfo1.GetBundleName(), newInfo1);
    InnerBundleInfo newInfo2;
    newInfo2.baseApplicationInfo_->bundleName = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    newInfo2.SetCurrentModulePackage(fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH));
    newInfos.emplace(newInfo2.GetBundleName(), newInfo2);
    InnerBundleInfo oldInfo1;
    oldInfo1.baseApplicationInfo_->bundleName = newInfo1.GetBundleName();
    oldInfo1.SetCurrentModulePackage(newInfo1.GetCurrentModulePackage());
    installer.CopyAllDriverFile(newInfos, oldInfo1);
    installer.RemoveAndReNameDriverFile(newInfos, oldInfo1);
    InnerBundleInfo oldInfo2;
    oldInfo2.baseApplicationInfo_->bundleName = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    oldInfo2.SetCurrentModulePackage(fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH));
    installer.CopyAllDriverFile(newInfos, oldInfo2);
    installer.RemoveAndReNameDriverFile(newInfos, oldInfo2);

    Metadata metaData;
    metaData.name = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    metaData.value = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    metaData.resource = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    std::unordered_multimap<std::string, std::string> dirMap;
    bool isModuleExisted = fdp.ConsumeBool();
    installer.FilterDriverSoFile(newInfo1, metaData, dirMap, isModuleExisted);
    metaData.name = "cupsFilter";
    installer.FilterDriverSoFile(newInfo1, metaData, dirMap, isModuleExisted);
    metaData.value = "../invalid_path";
    installer.FilterDriverSoFile(newInfo1, metaData, dirMap, isModuleExisted);
    metaData.resource = "../invalid_path";
    installer.FilterDriverSoFile(newInfo1, metaData, dirMap, isModuleExisted);
    metaData.value = "valid_path";
    metaData.resource = "valid_path";
    installer.FilterDriverSoFile(newInfo1, metaData, dirMap, isModuleExisted);

    installer.RemoveDriverSoFile(newInfo1, newInfo1.GetCurrentModulePackage(), isModuleExisted);
    InnerExtensionInfo innerExtensionInfo;
    innerExtensionInfo.moduleName = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    innerExtensionInfo.bundleName = newInfo1.GetBundleName();
    std::string extensionKey = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    newInfo1.InsertExtensionInfo(extensionKey, innerExtensionInfo);
    installer.RemoveDriverSoFile(newInfo1, innerExtensionInfo.moduleName, isModuleExisted);
    innerExtensionInfo.type = ExtensionAbilityType::DRIVER;
    newInfo1.InsertExtensionInfo(extensionKey, innerExtensionInfo);
    installer.RemoveDriverSoFile(newInfo1, innerExtensionInfo.moduleName, isModuleExisted);
    innerExtensionInfo.metadata.push_back(metaData);
    newInfo1.InsertExtensionInfo(extensionKey, innerExtensionInfo);
    installer.RemoveDriverSoFile(newInfo1, innerExtensionInfo.moduleName, isModuleExisted);

    installer.CreateDriverSoDestinedDir("", "", "", "", isModuleExisted);
    std::string bundleName = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    std::string moduleName = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    std::string fileName = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    std::string destinedDir = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    isModuleExisted = fdp.ConsumeBool();
    installer.CreateDriverSoDestinedDir(bundleName, moduleName, fileName, destinedDir, isModuleExisted);
    destinedDir = "../invalid_path";
    installer.CreateDriverSoDestinedDir(bundleName, moduleName, fileName, destinedDir, isModuleExisted);

    std::string srcPath = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    isModuleExisted = fdp.ConsumeBool();
    installer.CopyDriverSoFile(newInfo1, fileName, isModuleExisted);
    installer.CopyDriverSoFile(newInfo2, fileName, isModuleExisted);

    installer.RenameDriverFile(newInfo1);
    installer.RenameDriverFile(newInfo2);

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
