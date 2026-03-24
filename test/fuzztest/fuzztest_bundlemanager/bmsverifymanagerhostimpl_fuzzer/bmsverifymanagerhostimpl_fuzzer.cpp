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

#include "bmsverifymanagerhostimpl_fuzzer.h"

#define private public

#include <cstddef>
#include <cstdint>
#include <fuzzer/FuzzedDataProvider.h>

#include "verify_manager_host_impl.h"
#include "securec.h"
#include "bms_fuzztest_util.h"

using namespace OHOS::AppExecFwk;
using namespace OHOS::AppExecFwk::BMSFuzzTestUtil;
namespace OHOS {
bool DoSomethingInterestingWithMyAPI(const uint8_t* data, size_t size)
{
    VerifyManagerHostImpl impl;
    FuzzedDataProvider fdp(data, size);
    std::vector<std::string> abcPaths = GenerateStringArray(fdp);
    impl.CheckFileParam(abcPaths);
    std::string bundleName = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    int32_t userId = GenerateRandomUser(fdp);
    impl.CopyFilesToTempDir(bundleName, userId, abcPaths);
    std::string dir = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    std::vector<std::string> paths = GenerateStringArray(fdp);
    impl.MkdirIfNotExist(dir);
    impl.RemoveTempFiles(bundleName);
    impl.RemoveTempFiles(paths);
    std::string path = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    int32_t funcResult = fdp.ConsumeIntegral<int32_t>();
    int32_t funcResult1 = ERR_APPEXECFWK_IDL_GET_RESULT_ERROR;
    impl.DeleteAbc(path, funcResult);
    impl.DeleteAbc(path, funcResult1);
    impl.GetBundleMutex(bundleName);
    impl.GetCallingBundleName(bundleName);
    std::string sourcePath = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    std::string fileDir = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    impl.GetFileDir(sourcePath, fileDir);
    std::string fileName = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    impl.GetFileName(sourcePath, fileName);
    std::string relativePath = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    impl.GetRealPath(bundleName, userId, relativePath);
    impl.GetBundleMutex(bundleName);
    impl.InnerVerify(bundleName, abcPaths);
    impl.MoveAbc(bundleName, abcPaths);
    impl.RemoveTempFiles(bundleName);
    impl.Rollback(paths);
    std::vector<std::string> names = GenerateStringArray(fdp);
    std::string rootDir = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    impl.Rollback(rootDir, names);
    impl.Verify(abcPaths, funcResult);
    impl.VerifyAbc(abcPaths);
    impl.VerifyAbc(rootDir, names);
    return true;
}
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    OHOS::DoSomethingInterestingWithMyAPI(data, size);
    return 0;
}
