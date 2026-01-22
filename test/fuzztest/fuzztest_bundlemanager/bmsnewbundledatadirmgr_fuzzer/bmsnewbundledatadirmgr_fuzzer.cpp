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

#define private public
#include <cstddef>
#include <cstdint>
#include <fuzzer/FuzzedDataProvider.h>
#define private public
#include "new_bundle_data_dir_mgr.h"
#undef private
#include "bmsnewbundledatadirmgr_fuzzer.h"
#include "bms_fuzztest_util.h"

using namespace OHOS::AppExecFwk;
using namespace OHOS::AppExecFwk::BMSFuzzTestUtil;
namespace OHOS {
bool DoSomethingInterestingWithMyAPI(const uint8_t* data, size_t size)
{
    auto newBundleDirMgr = DelayedSingleton<NewBundleDataDirMgr>::GetInstance();
    FuzzedDataProvider fdp(data, size);
    std::string bundleName = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    int32_t userId = GenerateRandomUser(fdp);
    newBundleDirMgr->GetAllNewBundleDataDirBundleName();
    newBundleDirMgr->GetNewBundleDataDirType(bundleName, userId);
    newBundleDirMgr->GetBundleMutex(bundleName);
    newBundleDirMgr->LoadNewBundleDataDirInfosFromDb();
    uint32_t dirType = fdp.ConsumeIntegral<uint32_t>();
    newBundleDirMgr->AddNewBundleDirInfo(bundleName, dirType);
    newBundleDirMgr->AddNewBundleDataDirInfosToDb();
    newBundleDirMgr->DeleteNewBundleDataDirInfosFromDb();
    newBundleDirMgr->ProcessOtaBundleDataDir(bundleName, userId);
    newBundleDirMgr->InnerProcessOtaNewInstallBundleDir(bundleName, userId);
    newBundleDirMgr->InnerProcessOtaBundleDataDirEl5(bundleName, userId);
    newBundleDirMgr->InnerProcessOtaBundleDataDirGroup(bundleName, userId);
    std::set<int32_t> userIds;
    std::set<int32_t> userIds1 = {1, 2, 3};
    newBundleDirMgr->AddAllUserId(userIds);
    newBundleDirMgr->AddAllUserId(userIds1);
    newBundleDirMgr->DeleteUserId(userId);
    newBundleDirMgr->GetAllBundleDataDirEl5BundleName(userId);
    newBundleDirMgr->ProcessOtaBundleDataDirEl5(userId);
    return true;
}
}

// Fuzzer entry point.
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::DoSomethingInterestingWithMyAPI(data, size);
    return 0;
}
