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
#include "copytotempdir_fuzzer.h"

using namespace OHOS::AppExecFwk;

namespace OHOS {
namespace {
    const std::string FILE_PATH = "/data/service/el1/public/bms/bundle_manager_service/a.hsp";
    const std::string DIR_PATH_TWO = "/data/test/test";
    const std::string BUNDLE_NAME = "com.ohos.resourcedemo";
}
    bool fuzzelCopyToTempDirCaseOne(const uint8_t* data, size_t size)
    {
        ExtendResourceManagerHostImpl impl;
        std::vector<std::string> oldFilePaths;
        oldFilePaths.push_back(FILE_PATH);
        std::vector<std::string> newFilePaths = {std::string(reinterpret_cast<const char*>(data), size)};
        newFilePaths.push_back(DIR_PATH_TWO);
        auto ret = impl.CopyToTempDir(BUNDLE_NAME, oldFilePaths, newFilePaths);
        if (ret == ERR_OK) {
            return true;
        }
        return false;
    }
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    OHOS::fuzzelCopyToTempDirCaseOne(data, size);
    return 0;
}