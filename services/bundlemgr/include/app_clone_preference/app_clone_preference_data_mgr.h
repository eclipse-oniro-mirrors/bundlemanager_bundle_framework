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

#ifndef FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_APP_CLONE_PREFERENCE_DATA_MGR_H
#define FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_APP_CLONE_PREFERENCE_DATA_MGR_H

#include <memory>
#include <string>
#include <vector>

#include "app_clone_preference.h"
#include "app_clone_preference_storage.h"
#include "errors.h"

namespace OHOS {
namespace AppExecFwk {
class BundleDataMgr;

class AppClonePreferenceDataMgr {
public:
    AppClonePreferenceDataMgr();
    ~AppClonePreferenceDataMgr() = default;

    ErrCode GetAppClonePreference(const std::string &bundleName, int32_t userId,
        AppClonePreference &preference);
    ErrCode SetAppClonePreference(const std::string &bundleName, int32_t userId,
        const AppClonePreference &preference);
    ErrCode DeleteAppClonePreference(const std::string &bundleName, int32_t userId);
    ErrCode HandleAppCloneUninstalled(const std::string &bundleName, int32_t userId,
        int32_t uninstalledAppIndex);

private:
    std::shared_ptr<AppClonePreferenceStorage> storage_;
};
}  // namespace AppExecFwk
}  // namespace OHOS

#endif  // FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_APP_CLONE_PREFERENCE_DATA_MGR_H
