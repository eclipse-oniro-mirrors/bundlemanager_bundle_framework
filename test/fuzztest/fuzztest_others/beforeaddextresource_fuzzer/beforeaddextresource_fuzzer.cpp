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
#include "beforeaddextresource_fuzzer.h"

using namespace OHOS::AppExecFwk;

namespace OHOS {
namespace {
    const std::string FILE_PATH = "/data/service/el1/public/bms/bundle_manager_service/a.hsp";
    const std::string BUNDLE_NAME = "com.ohos.resourcedemo";
    const std::string INVALID_PATH = "/data/service/el1/public/bms/bundle_manager_service/../../a.hsp";
    const std::string EMPTY_STRING = "";
}
    bool fuzzelBeforeAddExtResourceCaseOne(const uint8_t* data, size_t size)
    {
        ExtendResourceManagerHostImpl impl;
        std::vector<std::string> filePaths = {std::string(reinterpret_cast<const char*>(data), size)};
        auto ret = impl.BeforeAddExtResource(EMPTY_STRING, filePaths);
        if (ret == ERR_OK) {
            return true;
        }
        return false;
    }

    bool fuzzelBeforeAddExtResourceCaseTwo(const uint8_t* data, size_t size)
    {
        ExtendResourceManagerHostImpl impl;
        std::vector<std::string> filePaths = {std::string(reinterpret_cast<const char*>(data), size)};
        auto ret = impl.BeforeAddExtResource(BUNDLE_NAME, filePaths);
        if (ret == ERR_OK) {
            return true;
        }
        return false;
    }

    bool fuzzelBeforeAddExtResourceCaseThree(const uint8_t* data, size_t size)
    {
        ExtendResourceManagerHostImpl impl;
        std::vector<std::string> filePaths = {std::string(reinterpret_cast<const char*>(data), size)};
        filePaths.emplace_back(FILE_PATH);
        filePaths.emplace_back(INVALID_PATH);
        auto ret = impl.BeforeAddExtResource(BUNDLE_NAME, filePaths);
        if (ret == ERR_OK) {
            return true;
        }
        return false;
    }
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    OHOS::fuzzelBeforeAddExtResourceCaseOne(data, size);
    OHOS::fuzzelBeforeAddExtResourceCaseTwo(data, size);
    OHOS::fuzzelBeforeAddExtResourceCaseThree(data, size);
    return 0;
}