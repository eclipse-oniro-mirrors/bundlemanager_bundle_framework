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
#include "checkfileparam_fuzzer.h"

using namespace OHOS::AppExecFwk;

namespace OHOS {
namespace {
    const std::string INVALID_SUFFIX = "/data/service/el1/public/bms/bundle_manager_service/a.hap";
    const std::string INVALID_PREFIX = "/data/app/el1/bundle/public/a.hsp";
    const std::string INVALID_PATH = "/data/service/el1/public/bms/bundle_manager_service/../../a.hsp";
}
    bool fuzzelCheckFileParamCaseOne(const uint8_t* data, size_t size)
    {
        ExtendResourceManagerHostImpl impl;
        auto ret = impl.CheckFileParam(INVALID_PATH);
        if (ret == ERR_OK) {
            return true;
        }
        return false;
    }

    bool fuzzelCheckFileParamCaseTwo(const uint8_t* data, size_t size)
    {
        ExtendResourceManagerHostImpl impl;
        auto ret = impl.CheckFileParam(INVALID_SUFFIX);
        if (ret == ERR_OK) {
            return true;
        }
        return false;
    }

    bool fuzzelCheckFileParamCaseThree(const uint8_t* data, size_t size)
    {
        ExtendResourceManagerHostImpl impl;
        auto ret = impl.CheckFileParam(INVALID_PREFIX);
        if (ret == ERR_OK) {
            return true;
        }
        return false;
    }
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    OHOS::fuzzelCheckFileParamCaseOne(data, size);
    OHOS::fuzzelCheckFileParamCaseTwo(data, size);
    OHOS::fuzzelCheckFileParamCaseThree(data, size);
    return 0;
}