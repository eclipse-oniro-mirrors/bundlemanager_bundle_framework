/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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
#include "bmsupdateextresourcesdb_fuzzer.h"

#define private public

#include <cstddef>
#include <cstdint>
#include <fuzzer/FuzzedDataProvider.h>

#include "extend_resource_manager_host_impl.h"
#include "securec.h"
#include "bms_fuzztest_util.h"

using namespace OHOS::AppExecFwk;
using namespace OHOS::AppExecFwk::BMSFuzzTestUtil;
namespace OHOS {
const std::string FILE_PATH = "/data/service/el1/public/bms/bundle_manager_service/a.hsp";
const std::string DIR_PATH_TWO = "/data/test/test";
const std::string BUNDLE_NAME = "com.ohos.resourcedemo";
bool DoSomethingInterestingWithMyAPI(const uint8_t* data, size_t size)
{
    ExtendResourceManagerHostImpl impl;
    FuzzedDataProvider fdp(data, size);
    std::vector<std::string> oldFilePaths;
    oldFilePaths.push_back(FILE_PATH);
    std::vector<std::string> newFilePaths = GenerateStringArray(fdp);
    newFilePaths.push_back(DIR_PATH_TWO);
    impl.CopyToTempDir(BUNDLE_NAME, oldFilePaths, newFilePaths);
    std::vector<ExtendResourceInfo> extendResourceInfos;
    impl.UpdateExtResourcesDb(BUNDLE_NAME, extendResourceInfos);
    return true;
}
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    OHOS::DoSomethingInterestingWithMyAPI(data, size);
    return 0;
}