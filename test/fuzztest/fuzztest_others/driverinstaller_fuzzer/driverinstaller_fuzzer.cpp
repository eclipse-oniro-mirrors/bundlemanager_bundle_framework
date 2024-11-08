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
#include <iostream>
#include "driver_installer.h"

#include "driverinstaller_fuzzer.h"
#include "securec.h"

using namespace OHOS::AppExecFwk;
using namespace OHOS::AAFwk;
namespace OHOS {
constexpr size_t U32_AT_SIZE = 4;
constexpr uint8_t ENABLE = 2;
    bool DoSomethingInterestingWithMyAPI(const char* data, size_t size)
    {
        std::shared_ptr driverInstaller = std::make_shared<DriverInstaller>();
        InnerBundleInfo info;
        std::string bundleName(reinterpret_cast<const char*>(data), size);
        std::string moduleName(reinterpret_cast<const char*>(data), size);
        std::string fileName(reinterpret_cast<const char*>(data), size);
        std::string destinedDir(reinterpret_cast<const char*>(data), size);
        bool isModuleExisted = *data % ENABLE;
        auto res = driverInstaller->CreateDriverSoDestinedDir(bundleName,
        moduleName, fileName, destinedDir, isModuleExisted);

        driverInstaller->RemoveDriverSoFile(info, moduleName, isModuleExisted);

        Metadata meta;
        std::unordered_multimap<std::string, std::string> dirMap;
        driverInstaller->FilterDriverSoFile(info, meta, dirMap, isModuleExisted);

        std::unordered_map<std::string, InnerBundleInfo> newInfos;
        InnerBundleInfo oldInfo;
        driverInstaller->CopyAllDriverFile(newInfos, oldInfo);

        std::string srcPath(reinterpret_cast<const char*>(data), size);
        driverInstaller->CopyDriverSoFile(info, srcPath, isModuleExisted);

        driverInstaller->RemoveAndReNameDriverFile(newInfos, oldInfo);

        driverInstaller->RenameDriverFile(info);

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

    /* Validate the length of size */
    if (size < OHOS::U32_AT_SIZE) {
        return 0;
    }

    char* ch = (char*)malloc(size + 1);
    if (ch == nullptr) {
        std::cout << "malloc failed." << std::endl;
        return 0;
    }

    (void)memset_s(ch, size + 1, 0x00, size + 1);
    if (memcpy_s(ch, size + 1, data, size) != EOK) {
        std::cout << "copy failed." << std::endl;
        free(ch);
        ch = nullptr;
        return 0;
    }

    OHOS::DoSomethingInterestingWithMyAPI(ch, size);
    free(ch);
    ch = nullptr;
    return 0;
}