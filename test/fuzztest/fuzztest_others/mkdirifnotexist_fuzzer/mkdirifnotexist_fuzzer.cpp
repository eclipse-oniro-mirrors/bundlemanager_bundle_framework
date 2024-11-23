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
#include "mkdirifnotexist_fuzzer.h"

using namespace OHOS::AppExecFwk;

namespace OHOS {
namespace {
    const std::string DIR_PATH = "/data/service/el1";
}
    bool fuzzelMkDirIfNotExistCaseOne(const uint8_t* data, size_t size)
    {
        ExtendResourceManagerHostImpl impl;
        auto ret = impl.MkdirIfNotExist(DIR_PATH);
        if (ret != ERR_APPEXECFWK_INSTALLD_GET_PROXY_ERROR) {
            return false;
        }
        ret = impl.MkdirIfNotExist(std::string(reinterpret_cast<const char*>(data), size));
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