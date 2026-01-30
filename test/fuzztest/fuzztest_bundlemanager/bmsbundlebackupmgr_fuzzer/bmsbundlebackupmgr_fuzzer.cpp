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
#include "bundle_backup_mgr.h"
#undef private
#include "bmsbundlebackupmgr_fuzzer.h"
#include "bms_fuzztest_util.h"
#include "securec.h"

using namespace OHOS::AppExecFwk;
using namespace OHOS::AppExecFwk::BMSFuzzTestUtil;
namespace OHOS {
bool DoSomethingInterestingWithMyAPI(const uint8_t* data, size_t size)
{
    FuzzedDataProvider fdp(data, size);
    std::shared_ptr<BundleBackupMgr> bundleBackupMgr = DelayedSingleton<BundleBackupMgr>::GetInstance();
    MessageParcel datas;
    datas.WriteBuffer(data, size);
    datas.RewindRead(0);
    MessageParcel reply;
    bundleBackupMgr->OnBackup(datas, reply);
    bundleBackupMgr->OnRestore(datas, reply);
    std::string config = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    bundleBackupMgr->SaveToFile(config);
    int32_t fd = fdp.ConsumeIntegral<int32_t>();
    bundleBackupMgr->LoadFromFile(fd, config);
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
