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
#include "bmsinstalldlinkdedupedso_fuzzer.h"

#include <cstddef>
#include <cstdint>
#include <fuzzer/FuzzedDataProvider.h>

#include "ipc/installd_host.h"
#include "bms_fuzztest_util.h"
#include "message_parcel.h"

using namespace OHOS::AppExecFwk;
using namespace OHOS::AppExecFwk::BMSFuzzTestUtil;

namespace OHOS {

// HandleLinkDedupedSo reads bundleName/libraryPath/sha256 (String16) then writes
// back the error code and the musl result code on the production path
void FuzzLinkDedupedSo(InstalldHost& installdHost, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<InstalldHost>(data);
    MessageParcel reply;
    WriteString16Field(data, fdp);  // bundleName
    WriteString16Field(data, fdp);  // libraryPath
    WriteString16Field(data, fdp);  // sha256
    FinishParcel(data);
    installdHost.HandleLinkDedupedSo(data, reply);
}

bool DoSomethingInterestingWithMyAPI(const uint8_t* data, const size_t size)
{
    if (data == nullptr || size == 0) {
        return false;
    }
    FuzzedDataProvider fdp(data, size);
    static InstalldHost installdHost;
    FuzzLinkDedupedSo(installdHost, fdp);
    return true;
}
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    OHOS::DoSomethingInterestingWithMyAPI(data, size);
    return 0;
}
