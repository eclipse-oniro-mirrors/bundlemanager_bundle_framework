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
#include "savecurdynamicicon_fuzzer.h"

using namespace OHOS::AppExecFwk;

namespace OHOS {
namespace {
    const std::string BUNDLE_NAME2 = "com.ohos.mms";
    const std::string TEST_MODULE = "testModule";
}
    bool fuzzelSaveCurDynamicIconCaseOne(const uint8_t* data, size_t size)
    {
        ExtendResourceManagerHostImpl impl;
        impl.SaveCurDynamicIcon(BUNDLE_NAME2, TEST_MODULE);
        return true;
    }
    bool fuzzelSaveCurDynamicIconCaseTwo(const uint8_t* data, size_t size)
    {
        ExtendResourceManagerHostImpl impl;
        impl.SaveCurDynamicIcon(BUNDLE_NAME2, "");
        return true;
    }
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    OHOS::fuzzelSaveCurDynamicIconCaseOne(data, size);
    OHOS::fuzzelSaveCurDynamicIconCaseTwo(data, size);
    return 0;
}