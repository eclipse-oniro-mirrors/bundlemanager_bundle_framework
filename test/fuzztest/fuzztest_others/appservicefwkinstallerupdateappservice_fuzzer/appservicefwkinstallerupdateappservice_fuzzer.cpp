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
#include <cstddef>
#include <cstdint>

#include "app_service_fwk/app_service_fwk_installer.h"

#include "appservicefwkinstallerupdateappservice_fuzzer.h"
#include "securec.h"

using namespace OHOS::AppExecFwk;
namespace OHOS {
    constexpr size_t FOO_MAX_LEN = 1024;
    constexpr size_t U32_AT_SIZE = 4;
    const int32_t VERSION_LOW = 0;
    const std::string MODULE_NAME_TEST = "moduleName";
    const std::string TEST_CREATE_FILE_PATH = "/data/test/resource/bms/app_service_test/test_create_dir/test.hap";
    const std::string VERSION_ONE_LIBRARY_ONE_PATH =
      "/data/test/resource/bms/app_service_test/test_create_dir/test.hap";

    bool DoSomethingInterestingWithMyAPI(const char* data, size_t size)
    {
        AppServiceFwkInstaller appServiceFwk;
        InstallParam installParam;
        std::unordered_map<std::string, InnerBundleInfo> infos;
        InnerBundleInfo innerBundleInfo;
        innerBundleInfo.currentPackage_ = MODULE_NAME_TEST;
        infos.emplace(TEST_CREATE_FILE_PATH, innerBundleInfo);
        appServiceFwk.UpdateAppService(innerBundleInfo, infos, installParam);
        InnerBundleInfo oldInfo;
        InnerBundleInfo newInfo;
        appServiceFwk.CheckNeedUpdate(newInfo, oldInfo);
        std::string hspPath = ", path: ";
        appServiceFwk.ProcessBundleUpdateStatus(oldInfo, newInfo, VERSION_ONE_LIBRARY_ONE_PATH);
        bool isReplace = true;
        bool noSkipsKill = false;
        appServiceFwk.ProcessModuleUpdate(innerBundleInfo, oldInfo, hspPath);
        appServiceFwk.RemoveLowerVersionSoDir(VERSION_LOW);
        std::string bundlePath(data, size);
        std::string cpuAbi(data, size);
        std::string targetSoPath(data, size);
        bool isPreInstalledBundle = false;
        appServiceFwk.VerifyCodeSignatureForNativeFiles(bundlePath, cpuAbi, targetSoPath);
        std::vector<Security::Verify::HapVerifyResult> hapVerifyResults;
        appServiceFwk.DeliveryProfileToCodeSign(hapVerifyResults);
        appServiceFwk.GenerateOdid(infos, hapVerifyResults);
        return true;
    }
}

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

    /* Validate the length of size */
    if (size > OHOS::FOO_MAX_LEN) {
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