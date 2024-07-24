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

#include <cstddef>
#include <cstdint>

#include "app_control_proxy.h"

#include "defaultapphostimpl_fuzzer.h"
#include "default_app_host_impl.h"

using namespace OHOS::AppExecFwk;
namespace OHOS {
    bool DoSomethingInterestingWithMyAPI(const uint8_t *data, size_t size)
    {
        std::string type(reinterpret_cast<const char *>(data), size);
        BundleInfo bundleInfo;
        Element element;
        element.bundleName = "";
        AAFwk::Want want;
        want.SetElementName("", "");

        bool isDefaultApp = false;
        auto defaultAppHostImpl_ = std::make_shared<DefaultAppHostImpl>();
        defaultAppHostImpl_->GetDefaultApplication(reinterpret_cast<uintptr_t>(data), type, bundleInfo);
        defaultAppHostImpl_->IsDefaultApplication(type, isDefaultApp);
        defaultAppHostImpl_->SetDefaultApplication(reinterpret_cast<uintptr_t>(data), type, want);
        defaultAppHostImpl_->ResetDefaultApplication(reinterpret_cast<uintptr_t>(data), type);

        return true;
    }
}

// Fuzzer entry point.
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    // Run your code on data.
    OHOS::DoSomethingInterestingWithMyAPI(data, size);
    return 0;
}