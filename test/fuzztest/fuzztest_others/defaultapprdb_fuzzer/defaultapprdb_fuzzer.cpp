/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include "defaultapprdb_fuzzer.h"
#include "default_app_rdb.h"

using namespace OHOS::AppExecFwk;
namespace OHOS {
    bool DoSomethingInterestingWithMyAPI(const uint8_t *data, size_t size)
    {
        bool ret = false;
        std::string type = "IMAGE";

        BundleInfo bundleInfo;
        Element element;
        element.bundleName = "";
        auto defaultAppDb_ = std::make_shared<DefaultAppRdb>();
        defaultAppDb_->GetDefaultApplicationInfo(reinterpret_cast<uintptr_t>(data), type, element);
        std::map<std::string, Element> currentInfos;
        defaultAppDb_->GetDefaultApplicationInfos(reinterpret_cast<uintptr_t>(data), currentInfos);
        std::map<std::string, Element> newInfos;
        defaultAppDb_->SetDefaultApplicationInfos(reinterpret_cast<uintptr_t>(data), newInfos);
        defaultAppDb_->SetDefaultApplicationInfo(reinterpret_cast<uintptr_t>(data), type, element);
        defaultAppDb_->DeleteDefaultApplicationInfos(reinterpret_cast<uintptr_t>(data));
        defaultAppDb_->DeleteDefaultApplicationInfo(reinterpret_cast<uintptr_t>(data), type);
        defaultAppDb_->RegisterDeathListener();
        defaultAppDb_->UnRegisterDeathListener();
        defaultAppDb_->LoadDefaultApplicationConfig();
        defaultAppDb_->LoadBackUpDefaultApplicationConfig();
        defaultAppDb_->ConvertMimeTypeToUtd();
        defaultAppDb_->DeleteDataFromDb(reinterpret_cast<uintptr_t>(data));
        defaultAppDb_->SaveDataToDb(reinterpret_cast<uintptr_t>(data), newInfos);
        defaultAppDb_->GetDataFromDb(reinterpret_cast<uintptr_t>(data), newInfos);
        DefaultAppData defaultAppData;
        const std::string DEFAULT_APP_JSON_PATH = "/etc/app/backup_default_app.json";
        defaultAppDb_->ParseConfig(DEFAULT_APP_JSON_PATH, defaultAppData);
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