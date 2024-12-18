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

#define private public
#include "shortcutdatastoragerdb_fuzzer.h"

#include "shortcut_data_storage_rdb.h"
#include "securec.h"

using namespace OHOS::AppExecFwk;
namespace OHOS {
constexpr size_t U32_AT_SIZE = 4;
const int32_t USERID = 100;

bool DoSomethingInterestingWithMyAPI(const char* data, size_t size)
{
    std::shared_ptr<ShortcutDataStorageRdb> shortcutDataStorageRdb = std::make_shared<ShortcutDataStorageRdb>();
    ShortcutInfo shortcutInfo;
    shortcutInfo.id = "id_test1";
    shortcutInfo.bundleName = "com.ohos.hello";
    shortcutInfo.hostAbility = "hostAbility";
    shortcutInfo.icon = "$media:16777224";
    shortcutInfo.label = "shortcutLabel";
    shortcutInfo.disableMessage = std::string(reinterpret_cast<const char *>(data), size);
    shortcutInfo.isStatic = true;
    shortcutInfo.isHomeShortcut = true;
    shortcutInfo.isEnables = true;
    bool isIdIllegal = false;
    shortcutDataStorageRdb->AddDesktopShortcutInfo(shortcutInfo, USERID, isIdIllegal);
    shortcutDataStorageRdb->DeleteDesktopShortcutInfo(shortcutInfo, USERID);
    std::vector<ShortcutInfo> shortcutInfos;
    shortcutDataStorageRdb->GetAllDesktopShortcutInfo(USERID, shortcutInfos);
    shortcutDataStorageRdb->DeleteDesktopShortcutInfo(shortcutInfo.bundleName);
    shortcutDataStorageRdb->DeleteDesktopShortcutInfo(shortcutInfo.bundleName, USERID, shortcutInfo.appIndex);
    shortcutDataStorageRdb->ShortcutIdVerification(shortcutInfo, USERID);
    shortcutDataStorageRdb->GetDesktopShortcutInfosByDefaultUserId(shortcutInfos);
    return true;
}
} // namespace OHOS

// Fuzzer entry point.
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    if (data == nullptr) {
        return 0;
    }

    if (size < OHOS::U32_AT_SIZE) {
        return 0;
    }

    char* ch = static_cast<char*>(malloc(size + 1));
    if (ch == nullptr) {
        return 0;
    }

    (void)memset_s(ch, size + 1, 0x00, size + 1);
    if (memcpy_s(ch, size, data, size) != EOK) {
        free(ch);
        ch = nullptr;
        return 0;
    }
    OHOS::DoSomethingInterestingWithMyAPI(ch, size);
    free(ch);
    ch = nullptr;
    return 0;
}