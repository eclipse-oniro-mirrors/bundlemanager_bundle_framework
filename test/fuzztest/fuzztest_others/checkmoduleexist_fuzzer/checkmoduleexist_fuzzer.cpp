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
#include "extend_resource_manager_host_impl.h"
#include "checkmoduleexist_fuzzer.h"

using namespace OHOS::AppExecFwk;

namespace OHOS {
namespace {
    const std::string TEST_BUNDLE = "com.test.ext.resource";
}
    bool fuzzelCheckModuleExistCaseOne(const uint8_t* data, size_t size)
    {
        ExtendResourceManagerHostImpl impl;
        std::string emptyBundleName;
        std::vector<std::string> moduleNames;
        std::vector<ExtendResourceInfo> extendResourceInfos;
        auto ret = impl.CheckModuleExist(TEST_BUNDLE, moduleNames, extendResourceInfos);
        if (ret != ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST) {
            return false;
        }
        return true;
    }
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    OHOS::fuzzelCheckModuleExistCaseOne(data, size);
    return 0;
}