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
#include <fuzzer/FuzzedDataProvider.h>

#include "account_helper.h"
#include "bms_fuzztest_util.h"
#include "bmsaccounthelper_fuzzer.h"
#include "securec.h"

using namespace OHOS::AppExecFwk;
using namespace OHOS::AppExecFwk::BMSFuzzTestUtil;
namespace OHOS {
bool DoSomethingInterestingWithMyAPI(const uint8_t* data, size_t size)
{
    bool isOsAccountExists = true;

    FuzzedDataProvider fdp(data, size);
    int32_t userId = BMSFuzzTestUtil::GenerateRandomUser(fdp);
    int32_t id = fdp.ConsumeIntegral<int32_t>();
    AccountHelper::IsOsAccountExists(id, isOsAccountExists);
    AccountHelper::GetCurrentActiveUserId();
    AccountHelper::IsOsAccountVerified(userId);
    int32_t uid = fdp.ConsumeIntegral<int32_t>();
    AccountHelper::GetOsAccountLocalIdFromUid(uid);
    return true;
}
} // namespace OHOS

// Fuzzer entry point.
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::DoSomethingInterestingWithMyAPI(data, size);
    return 0;
}