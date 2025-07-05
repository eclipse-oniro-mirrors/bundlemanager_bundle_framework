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

#include "first_install_data_mgr/first_install_data_mgr_storage_rdb.h"
#include "bmsaddfirstinstallbundleinfo_fuzzer.h"
#include "bms_fuzztest_util.h"

using namespace OHOS::AppExecFwk;
using namespace OHOS::AppExecFwk::BMSFuzzTestUtil;
namespace OHOS {
bool FuzzFirstInstallBundleInfo(const uint8_t *data, size_t size)
{
    auto firstInstallDataMgr = std::make_shared<FirstInstallDataMgrStorageRdb>();
    if (firstInstallDataMgr == nullptr) {
        return false;
    }
    FuzzedDataProvider fdp(data, size);
    std::string bundleName = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    int32_t userId = GenerateRandomUser(fdp);
    FirstInstallBundleInfo firstInstallBundleInfo;
    firstInstallBundleInfo.firstInstallTime = fdp.ConsumeIntegral<int64_t>();
    firstInstallDataMgr->AddFirstInstallBundleInfo(bundleName, userId, firstInstallBundleInfo);
    std::string bundleName2 = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    int32_t userId2 = GenerateRandomUser(fdp);
    FirstInstallBundleInfo BundleInfo;
    BundleInfo.firstInstallTime = fdp.ConsumeIntegral<int64_t>();
    firstInstallDataMgr->GetFirstInstallBundleInfo(bundleName2, userId2, BundleInfo);

    firstInstallDataMgr->rdbDataManager_ = nullptr;
    firstInstallDataMgr->IsExistFirstInstallBundleInfo(bundleName, userId);
    firstInstallDataMgr->AddFirstInstallBundleInfo(bundleName, userId, firstInstallBundleInfo);
    firstInstallDataMgr->GetFirstInstallBundleInfo(bundleName2, userId2, BundleInfo);
    firstInstallDataMgr->DeleteFirstInstallBundleInfo(userId);
    return true;
}
}

// Fuzzer entry point.
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    // Run your code on data.
    OHOS::FuzzFirstInstallBundleInfo(data, size);
    return 0;
}