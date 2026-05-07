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
#include "bms_fuzztest_util.h"
#include <fuzzer/FuzzedDataProvider.h>
#define private public
#include "extend_resource_manager_host_impl.h"
#include "mkdirifnotexist_fuzzer.h"

using namespace OHOS::AppExecFwk;
using namespace OHOS::AppExecFwk::BMSFuzzTestUtil;

namespace OHOS {
namespace {
    const std::string DIR_PATH = "/data/service/el1";
}
    bool fuzzelMkDirIfNotExistCaseOne(const uint8_t* data, size_t size)
    {
        ExtendResourceManagerHostImpl impl;
        FuzzedDataProvider fdp(data, size);
        std::string bundleName = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
        auto scene = static_cast<BundleDirScene>(fdp.ConsumeIntegral<int32_t>());
        auto ret = impl.MkdirIfNotExist(bundleName, scene, DIR_PATH);
        if (ret != ERR_APPEXECFWK_INSTALLD_GET_PROXY_ERROR) {
            return false;
        }
        std::string dir = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
        scene = static_cast<BundleDirScene>(fdp.ConsumeIntegral<int32_t>());
        ret = impl.MkdirIfNotExist(bundleName, scene, dir);
        if (ret != ERR_APPEXECFWK_INSTALLD_GET_PROXY_ERROR) {
            return false;
        }
        return true;
    }
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    OHOS::fuzzelMkDirIfNotExistCaseOne(data, size);
    return 0;
}