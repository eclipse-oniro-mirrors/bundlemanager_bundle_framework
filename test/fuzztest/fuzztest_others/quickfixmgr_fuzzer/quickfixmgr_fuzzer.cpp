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
#define protected public

#include "quickfixmgr_fuzzer.h"

#include <cstddef>
#include <cstdint>

#include "app_control_proxy.h"
#include "quick_fix_mgr.h"

using namespace OHOS::AppExecFwk;
namespace OHOS {
bool DoSomethingInterestingWithMyAPI(const uint8_t* data, size_t size)
{
    std::vector<std::string> bundleFilePaths;
    std::string bundleFilePath;
    bundleFilePaths.push_back(bundleFilePath);
    sptr<IQuickFixStatusCallback> statusCallback;
    bool isDebug = false;
    std::string targetPath;
    std::string bundleName;
    bool enable = false;
    auto quickFixMgr = std::make_shared<QuickFixMgr>();
    quickFixMgr->DeployQuickFix(bundleFilePaths, statusCallback, isDebug, targetPath);
    quickFixMgr->SwitchQuickFix(bundleName, enable, statusCallback);
    quickFixMgr->DeleteQuickFix(bundleName, statusCallback);
    quickFixMgr->CreateQuickFixer(statusCallback);
    return true;
}
} // namespace OHOS

// Fuzzer entry point.
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    // Run your code on data.
    OHOS::DoSomethingInterestingWithMyAPI(data, size);
    return 0;
}