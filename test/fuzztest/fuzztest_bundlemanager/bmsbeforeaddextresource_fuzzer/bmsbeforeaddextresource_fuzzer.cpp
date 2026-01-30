/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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
#include <cstddef>
#include <cstdint>
#include <fuzzer/FuzzedDataProvider.h>
#include "bms_fuzztest_util.h"
#include "extend_resource_manager_host_impl.h"
#include "bmsbeforeaddextresource_fuzzer.h"
#include "securec.h"

using namespace OHOS::AppExecFwk;
using namespace OHOS::AppExecFwk::BMSFuzzTestUtil;
namespace OHOS {
const std::string FILE_PATH = "/data/service/el1/public/bms/bundle_manager_service/a.hsp";
const std::string BUNDLE_NAME = "com.ohos.resourcedemo";
const std::string INVALID_PATH = "/data/service/el1/public/bms/bundle_manager_service/../../a.hsp";
const std::string EMPTY_STRING = "";
const std::string INVALID_SUFFIX = "/data/service/el1/public/bms/bundle_manager_service/a.hap";
const std::string INVALID_PREFIX = "/data/app/el1/bundle/public/a.hsp";
bool DoSomethingInterestingWithMyAPI(const uint8_t* data, size_t size)
{
    ExtendResourceManagerHostImpl impl;
    FuzzedDataProvider fdp(data, size);
    std::string bundleName = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    std::vector<std::string> filePaths = GenerateStringArray(fdp);
    impl.BeforeAddExtResource(bundleName, filePaths);
    impl.BeforeAddExtResource(EMPTY_STRING, filePaths);
    impl.BeforeAddExtResource(BUNDLE_NAME, filePaths);
    filePaths.emplace_back(FILE_PATH);
    filePaths.emplace_back(INVALID_PATH);
    auto ret = impl.BeforeAddExtResource(BUNDLE_NAME, filePaths);
    std::string dir = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    std::string filePath = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    impl.MkdirIfNotExist(dir);
    impl.CheckFileParam(INVALID_PATH);
    impl.CheckFileParam(INVALID_SUFFIX);
    impl.CheckFileParam(INVALID_PREFIX);
    impl.CheckFileParam(filePath);
    return true;
}
}

// Fuzzer entry point.
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    OHOS::DoSomethingInterestingWithMyAPI(data, size);
    return 0;
}