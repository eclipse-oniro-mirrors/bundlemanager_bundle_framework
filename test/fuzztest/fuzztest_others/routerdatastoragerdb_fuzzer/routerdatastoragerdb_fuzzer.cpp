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
#include "routerdatastoragerdb_fuzzer.h"

#include "router_data_storage_rdb.h"
#include "securec.h"

using namespace OHOS::AppExecFwk;
namespace OHOS {
constexpr size_t U32_AT_SIZE = 4;
constexpr uint8_t ENABLE = 2;
constexpr uint8_t CODE_MAX = 22;

bool DoSomethingInterestingWithMyAPI(const char* data, size_t size)
{
    auto routerDataStorageRdb = std::make_shared<RouterDataStorageRdb>();
    std::string bundleName(data, size);
    std::string moduleName(data, size);
    std::map<std::string, std::string> routerInfoMap;
    std::vector<RouterItem> routerInfos;
    routerDataStorageRdb->UpdateRouterInfo(bundleName, routerInfoMap);
    routerDataStorageRdb->GetRouterInfo(bundleName, moduleName, routerInfos);
    std::set<std::string> bundleNames;
    routerDataStorageRdb->GetAllBundleNames(bundleNames);
    routerDataStorageRdb->DeleteRouterInfo(bundleName);
    routerDataStorageRdb->DeleteRouterInfo(bundleName, moduleName);
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

    /* Validate the length of size */
    if (size < OHOS::U32_AT_SIZE) {
        return 0;
    }

    char* ch = (char*)malloc(size + 1);
    if (ch == nullptr) {
        std::cout << "malloc failed." << std::endl;
        return 0;
    }

    (void)memset_s(ch, size + 1, 0x00, size + 1);
    if (memcpy_s(ch, size + 1, data, size) != EOK) {
        std::cout << "copy failed." << std::endl;
        free(ch);
        ch = nullptr;
        return 0;
    }

    OHOS::DoSomethingInterestingWithMyAPI(ch, size);
    free(ch);
    ch = nullptr;
    return 0;
}