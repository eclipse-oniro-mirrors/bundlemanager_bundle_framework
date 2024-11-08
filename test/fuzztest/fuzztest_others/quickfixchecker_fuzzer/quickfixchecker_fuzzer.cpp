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

#include "quickfixchecker_fuzzer.h"
#define private public
#include "quick_fix_checker.h"
#include "securec.h"

using namespace OHOS::AppExecFwk;
namespace OHOS {
constexpr size_t U32_AT_SIZE = 4;
constexpr size_t MESSAGE_SIZE = 4;
constexpr size_t DCAMERA_SHIFT_24 = 24;
constexpr size_t DCAMERA_SHIFT_16 = 16;
constexpr size_t DCAMERA_SHIFT_8 = 8;
const std::string BUNDLE_NAME = "com.example.bmsaccesstoken1";
const uint32_t QUICK_FIX_VERSION_CODE = 1;
const uint32_t BUNDLE_VERSION_CODE = 1;
const std::string QUICK_FIX_VERSION_NAME = "1.0";
const std::string BUNDLE_VERSION_NAME = "1.0";

uint32_t GetU32Data(const char* ptr)
{
    return (ptr[0] << DCAMERA_SHIFT_24) | (ptr[1] << DCAMERA_SHIFT_16) | (ptr[2] << DCAMERA_SHIFT_8) | (ptr[3]);
}

AppQuickFix CreateAppQuickFix()
{
    AppqfInfo appInfo;
    appInfo.versionCode = QUICK_FIX_VERSION_CODE;
    appInfo.versionName = QUICK_FIX_VERSION_NAME;
    appInfo.type = QuickFixType::PATCH;
    HqfInfo hqfInfo;
    hqfInfo.moduleName = "entry";
    hqfInfo.type = QuickFixType::PATCH;
    appInfo.hqfInfos.push_back(hqfInfo);
    AppQuickFix appQuickFix;
    appQuickFix.bundleName = BUNDLE_NAME;
    appQuickFix.versionCode = BUNDLE_VERSION_CODE;
    appQuickFix.versionName = BUNDLE_VERSION_NAME;
    appQuickFix.deployingAppqfInfo = appInfo;
    return appQuickFix;
}

bool DoSomethingInterestingWithMyAPI(const char* data, size_t size)
{
    QuickFixChecker quickFixChecker;
    std::vector<std::string> bundlePaths;
    std::vector<Security::Verify::HapVerifyResult> hapVerifyRes;
    quickFixChecker.CheckMultipleHqfsSignInfo(bundlePaths, hapVerifyRes);
    std::unordered_map<std::string, AppQuickFix> infos;
    AppQuickFix appQuickFix = CreateAppQuickFix();
    infos.emplace("appQuickFix_1", appQuickFix);
    quickFixChecker.CheckAppQuickFixInfos(infos);
    quickFixChecker.CheckMultiNativeSo(infos);
    Security::Verify::ProvisionInfo provisionInfo;
    BundleInfo bundleInfo;
    quickFixChecker.CheckPatchWithInstalledBundle(appQuickFix, bundleInfo, provisionInfo);
    quickFixChecker.CheckHotReloadWithInstalledBundle(appQuickFix, bundleInfo);
    quickFixChecker.CheckSignatureInfo(bundleInfo, provisionInfo);
    quickFixChecker.GetAppDistributionType(Security::Verify::AppDistType::APP_GALLERY);
    quickFixChecker.CheckCommonWithInstalledBundle(appQuickFix, bundleInfo);
    quickFixChecker.CheckModuleNameExist(bundleInfo, infos);
    quickFixChecker.GetAppProvisionType(Security::Verify::ProvisionType::DEBUG);
    AppqfInfo qfInfo;
    qfInfo.cpuAbi = "arm";
    quickFixChecker.CheckPatchNativeSoWithInstalledBundle(bundleInfo, qfInfo);
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