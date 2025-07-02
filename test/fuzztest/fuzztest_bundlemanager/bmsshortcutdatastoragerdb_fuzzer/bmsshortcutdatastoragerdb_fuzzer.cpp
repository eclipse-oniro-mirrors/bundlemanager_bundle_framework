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

#include <cstddef>
#include <cstdint>
#include <set>
#include <fuzzer/FuzzedDataProvider.h>
#define private public
#include "bmsshortcutdatastoragerdb_fuzzer.h"
#include "shortcut_data_storage_rdb.h"
#include "bms_fuzztest_util.h"
#include "securec.h"

using namespace OHOS::AppExecFwk;
using namespace OHOS::AppExecFwk::BMSFuzzTestUtil;
namespace OHOS {
bool DoSomethingInterestingWithMyAPI(const uint8_t* data, size_t size)
{
    std::shared_ptr<ShortcutDataStorageRdb> shortcutDataStorageRdb =
        std::make_shared<ShortcutDataStorageRdb>();
    if (shortcutDataStorageRdb == nullptr) {
        return false;
    }
    FuzzedDataProvider fdp(data, size);
    ShortcutInfo shortcutInfo;
    int32_t userId = GenerateRandomUser(fdp);
    bool isIdIllegal = fdp.ConsumeBool();
    shortcutDataStorageRdb->AddDesktopShortcutInfo(shortcutInfo, userId, isIdIllegal);
    shortcutDataStorageRdb->DeleteDesktopShortcutInfo(shortcutInfo, userId);
    std::vector<ShortcutInfo> shortcutInfos;
    shortcutDataStorageRdb->GetAllDesktopShortcutInfo(userId, shortcutInfos);
    shortcutDataStorageRdb->DeleteDesktopShortcutInfo(shortcutInfo.bundleName);
    shortcutDataStorageRdb->DeleteDesktopShortcutInfo(shortcutInfo.bundleName, userId, shortcutInfo.appIndex);
    shortcutDataStorageRdb->ShortcutIdVerification(shortcutInfo, userId);
    shortcutDataStorageRdb->GetDesktopShortcutInfosByDefaultUserId(shortcutInfos);
    nlohmann::json jsonResult;
    shortcutDataStorageRdb->GetAllTableDataToJson(jsonResult);
    shortcutDataStorageRdb->UpdateAllShortcuts(jsonResult);
    return true;
}
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    // Run your code on data.
    OHOS::DoSomethingInterestingWithMyAPI(data, size);
    return 0;
}