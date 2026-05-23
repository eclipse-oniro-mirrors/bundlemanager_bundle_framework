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
#include <cstddef>
#include <cstdint>
#include <fuzzer/FuzzedDataProvider.h>
#include <iostream>

#include "bms_fuzztest_util.h"
#include "driver_installer.h"

#include "driverinstaller_fuzzer.h"
#include "securec.h"

using namespace OHOS::AppExecFwk;
using namespace OHOS::AAFwk;
using namespace OHOS::AppExecFwk::BMSFuzzTestUtil;
namespace OHOS {
constexpr size_t U32_AT_SIZE = 4;
constexpr uint8_t ENABLE = 2;
    bool DoSomethingInterestingWithMyAPI(const uint8_t* data, size_t size)
    {
        std::shared_ptr driverInstaller = std::make_shared<DriverInstaller>();
        InnerBundleInfo info;
        FuzzedDataProvider fdp(data, size);
        std::string bundleName = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
        std::string moduleName = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
        std::string fileName = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
        std::string destinedDir = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
        bool isModuleExisted = fdp.ConsumeBool();
        auto res = driverInstaller->CreateDriverSoDestinedDir(bundleName,
        moduleName, fileName, destinedDir, isModuleExisted);

        driverInstaller->RemoveDriverSoFile(info, moduleName, isModuleExisted);

        Metadata meta;
        std::unordered_multimap<std::string, std::string> dirMap;
        driverInstaller->FilterDriverSoFile(info, meta, dirMap, isModuleExisted);

        std::unordered_map<std::string, InnerBundleInfo> newInfos;
        InnerBundleInfo oldInfo;
        driverInstaller->CopyAllDriverFile(newInfos, oldInfo);

        std::string srcPath = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
        driverInstaller->CopyDriverSoFile(info, srcPath, isModuleExisted);

        driverInstaller->RemoveAndReNameDriverFile(newInfos, oldInfo);

        driverInstaller->RenameDriverFile(info);

        return true;
    }
}

// Fuzzer entry point.
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    OHOS::DoSomethingInterestingWithMyAPI(data, size);
    return 0;
}