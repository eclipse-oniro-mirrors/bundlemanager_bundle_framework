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
#include "hmpbundleinstaller_fuzzer.h"

#include "hmp_bundle_installer.h"
#include "inner_bundle_info.h"
#include "securec.h"

using namespace OHOS::AppExecFwk;
namespace OHOS {

constexpr size_t FOO_MAX_LEN = 1024;
constexpr size_t U32_AT_SIZE = 4;
constexpr uint8_t ENABLE = 2;
bool DoSomethingInterestingWithMyAPI(const char* data, size_t size)
{
    HmpBundleInstaller hmpBundleInstaller;
    std::set<std::string> hapList;
    std::set<std::string> systemHspList;
    std::unordered_map<std::string, InnerBundleInfo> infos;
    hmpBundleInstaller.InstallSystemHspInHmp(std::string(data, size));
    hmpBundleInstaller.InstallNormalAppInHmp(std::string(data, size));
    std::set<int32_t> userIds;
    hmpBundleInstaller.GetRequiredUserIds(std::string(data, size), userIds);
    hmpBundleInstaller.RollbackHmpBundle(systemHspList, hapList);
    hmpBundleInstaller.UpdateBundleInfo(std::string(data, size), std::string(data, size), std::string(data, size));
    hmpBundleInstaller.GetHmpBundleList(std::string(data, size));
    hmpBundleInstaller.UpdateInnerBundleInfo(std::string(data, size), infos);
    hmpBundleInstaller.ParseInfos(std::string(data, size), std::string(data, size), infos);
    hmpBundleInstaller.ParseHapFiles(std::string(data, size), infos);
    hmpBundleInstaller.UninstallSystemBundle(std::string(data, size), std::string(data, size));
    hmpBundleInstaller.CheckUninstallSystemHsp(std::string(data, size));
    hmpBundleInstaller.UpdatePreInfoInDb(std::string(data, size), infos);
    hmpBundleInstaller.UpdateBundleInfoForHmp(std::string(data, size), hapList, systemHspList);
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
    if (size < OHOS::U32_AT_SIZE || size > OHOS::FOO_MAX_LEN) {
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