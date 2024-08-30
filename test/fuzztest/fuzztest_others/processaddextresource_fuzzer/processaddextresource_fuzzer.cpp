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
#include "processaddextresource_fuzzer.h"

using namespace OHOS::AppExecFwk;

namespace OHOS {
namespace {
    const std::string TEST_BUNDLE = "com.test.ext.resource";
}
    bool fuzzelProcessAddExtResourceCaseOne(const uint8_t* data, size_t size)
    {
        ExtendResourceManagerHostImpl impl;
        std::vector<std::string> filePaths;
        auto ret = impl.ProcessAddExtResource(TEST_BUNDLE, filePaths);
        std::vector<ExtendResourceInfo> extendResourceInfos;
        impl.InnerSaveExtendResourceInfo(TEST_BUNDLE, filePaths, extendResourceInfos);
        impl.UpateExtResourcesDb(TEST_BUNDLE, extendResourceInfos);
        std::vector<std::string> moduleNames;
        impl.RemoveExtResourcesDb(TEST_BUNDLE, moduleNames);
        impl.InnerRemoveExtendResources(TEST_BUNDLE, moduleNames, extendResourceInfos);
        std::string moduleName(reinterpret_cast<const char*>(data), size);
        impl.EnableDynamicIcon(TEST_BUNDLE, moduleName);
        ExtendResourceInfo extendResourceInfo;
        impl.GetExtendResourceInfo(TEST_BUNDLE, moduleName, extendResourceInfo);
        return false;
    }
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    OHOS::fuzzelProcessAddExtResourceCaseOne(data, size);
    return 0;
}