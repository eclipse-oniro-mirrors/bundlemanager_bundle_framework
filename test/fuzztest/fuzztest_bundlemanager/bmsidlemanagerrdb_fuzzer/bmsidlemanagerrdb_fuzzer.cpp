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

#include <cstddef>
#include <cstdint>
#include <fuzzer/FuzzedDataProvider.h>
#define private public
#include "idle_manager_rdb.h"
#include "bmsidlemanagerrdb_fuzzer.h"
#undef private
#include "securec.h"
#include "bms_fuzztest_util.h"

using namespace OHOS::AppExecFwk;
using namespace OHOS::AppExecFwk::BMSFuzzTestUtil;
namespace OHOS {
bool DoSomethingInterestingWithMyAPI(const uint8_t* data, size_t size)
{
    FuzzedDataProvider fdp(data, size);
    std::shared_ptr<IdleManagerRdb> rdb = std::make_shared<IdleManagerRdb>();
    std::vector<BundleOptionInfo> bundleOptionInfos;
    rdb->AddBundles(bundleOptionInfos);
    BundleOptionInfo bundleOptionInfo;
    bundleOptionInfo.bundleName = "";
    rdb->AddBundle(bundleOptionInfo);
    BundleOptionInfo bundleOptionInfo1;
    bundleOptionInfo.bundleName = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    rdb->AddBundle(bundleOptionInfo1);
    rdb->DeleteBundle(bundleOptionInfo);
    rdb->DeleteBundle(bundleOptionInfo1);
    int32_t userId = GenerateRandomUser(fdp);
    rdb->DeleteBundle(userId);
    rdb->GetAllBundle(userId, bundleOptionInfos);
    std::shared_ptr<NativeRdb::ResultSet> absSharedResultSet;
    rdb->ConvertToBundleOptionInfo(absSharedResultSet, bundleOptionInfo1);
    return true;
}
}

// Fuzzer entry point.
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    OHOS::DoSomethingInterestingWithMyAPI(data, size);
    return 0;
}