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
#include "parseextendresourcefile_fuzzer.h"

using namespace OHOS::AppExecFwk;

namespace OHOS {
namespace {
    const std::string FILE_PATH = "/data/service/el1/public/bms/bundle_manager_service/a.hsp";
    const std::string BUNDLE_NAME = "com.ohos.resourcedemo";
}
    bool fuzzelParseExtendResourceFileCaseOne(const uint8_t* data, size_t size)
    {
        ExtendResourceManagerHostImpl impl;
        std::vector<std::string> filePaths;
        filePaths.emplace_back(FILE_PATH);
        std::vector<ExtendResourceInfo> extendResourceInfos;
        auto ret = impl.ParseExtendResourceFile(BUNDLE_NAME, filePaths, extendResourceInfos);
        if (ret != ERR_APPEXECFWK_INSTALL_FAILED_INVALID_SIGNATURE_FILE_PATH) {
            return false;
        }
        return true;
    }
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    OHOS::fuzzelParseExtendResourceFileCaseOne(data, size);
    return 0;
}