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

#include "extend_resource_manager_host_impl.h"
#include "RemoveExtResource_fuzzer.h"

using namespace OHOS::AppExecFwk;
namespace OHOS {
    namespace {
        const std::string FUZZTEST_BUNDLE = "com.test.ext.resource";
        const std::string FUZZTEST_MODULE = "testModule";
    }
    bool fuzzelRemoveExtResourceCaseOne(const uint8_t* data, size_t size)
    {
        ExtendResourceManagerHostImpl impl;
        std::string emptyBundleName;
        std::vector<std::string> moduleNames;
        auto ret = impl.RemoveExtResource(emptyBundleName, moduleNames);
        if (ret == ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST) {
            return true;
        }
        return false;
    }

    bool fuzzelRemoveExtResourceCaseTwo(const uint8_t* data, size_t size)
    {
        ExtendResourceManagerHostImpl impl;
        std::vector<std::string> moduleNames;
        auto ret = impl.RemoveExtResource(FUZZTEST_BUNDLE, moduleNames);
        if (ret == ERR_EXT_RESOURCE_MANAGER_REMOVE_EXT_RESOURCE_FAILED) {
            return true;
        }
        return false;
    }

    bool fuzzelRemoveExtResourceCaseThree(const uint8_t* data, size_t size)
    {
        ExtendResourceManagerHostImpl impl;
        std::vector<std::string> moduleNames;
        moduleNames.push_back(FUZZTEST_MODULE);
        auto ret = impl.RemoveExtResource(FUZZTEST_BUNDLE, moduleNames);
        if (ret == ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST) {
            return true;
        }
        return false;
    }
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    OHOS::fuzzelRemoveExtResourceCaseOne(data, size);
    OHOS::fuzzelRemoveExtResourceCaseTwo(data, size);
    OHOS::fuzzelRemoveExtResourceCaseThree(data, size);
    return 0;
}