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
#include "createfd_fuzzer.h"

using namespace OHOS::AppExecFwk;
namespace {
    const int32_t FD = 0;
    const std::string FILE_PATH = "data/test";
}

namespace OHOS {
    bool fuzzelCreateFdCaseOne(const uint8_t* data, size_t size)
    {
        ExtendResourceManagerHostImpl impl;
        int32_t fd = FD;
        std::string path = FILE_PATH;
        auto ret = impl.CreateFd(std::string(reinterpret_cast<const char*>(data), size), fd, path);
        if (ret == ERR_OK) {
            return true;
        }
        return false;
    }

    bool fuzzelCreateFdCaseTwo(const uint8_t* data, size_t size)
    {
        ExtendResourceManagerHostImpl impl;
        int32_t fd = FD;
        std::string path = FILE_PATH;
        auto ret = impl.CreateFd(std::string(reinterpret_cast<const char*>(data), size), fd, path);
        if (ret == ERR_OK) {
            return true;
        }
        return false;
    }
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    OHOS::fuzzelCreateFdCaseOne(data, size);
    OHOS::fuzzelCreateFdCaseTwo(data, size);
    return 0;
}