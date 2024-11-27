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
#include "disabledynamicicon_fuzzer.h"

using namespace OHOS::AppExecFwk;

namespace OHOS {
namespace {
    const std::string TEST_BUNDLE = "com.test.ext.resource";
}
    bool fuzzelDisableDynamicIconCaseOne(const uint8_t* data, size_t size)
    {
        ExtendResourceManagerHostImpl impl;
        std::string bundleName (reinterpret_cast<const char*>(data), size);
        auto ret = impl.DisableDynamicIcon(bundleName);
        if (ret == ERR_OK) {
            return true;
        }
        return false;
    }

    bool fuzzelDisableDynamicIconCaseTwo(const uint8_t* data, size_t size)
    {
        ExtendResourceManagerHostImpl impl;
        auto ret = impl.DisableDynamicIcon(TEST_BUNDLE);
        if (ret == ERR_OK) {
            return true;
        }
        return false;
    }
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    OHOS::fuzzelDisableDynamicIconCaseOne(data, size);
    OHOS::fuzzelDisableDynamicIconCaseTwo(data, size);
    return 0;
}