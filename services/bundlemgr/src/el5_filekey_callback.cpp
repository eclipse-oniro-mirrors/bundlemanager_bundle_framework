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

#include "el5_filekey_callback.h"
#include "installd_client.h"
#include "bundle_mgr_service.h"

namespace OHOS {
namespace AppExecFwk {
void El5FilekeyCallback::OnRegenerateAppKey(std::vector<Security::AccessToken::AppKeyInfo> &infos)
{
    APP_LOGI("OnRegenerateAppKey start");
    if (infos.empty()) {
        APP_LOGE("OnRegenerateAppKey infos is empty");
        return;
    }
    for (auto &info : infos) {
        std::string keyId = "";
        auto result = InstalldClient::GetInstance()->SetEncryptionPolicy(
            info.uid, info.bundleName, info.userId, keyId);
        if (result != ERR_OK) {
            APP_LOGE("SetEncryptionPolicy failed for %{public}s", info.bundleName.c_str());
        }
        // update the keyId to the bundleInfo
        auto dataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
        if (dataMgr == nullptr) {
            APP_LOGE("OnRegenerateAppKey dataMgr is nullptr");
            continue;
        }
        InnerBundleInfo bundleInfo;
        bool isAppExist = dataMgr->GetInnerBundleInfo(info.bundleName, bundleInfo);
        if (!isAppExist) {
            APP_LOGE("OnRegenerateAppKey bundleInfo is not exist");
            continue;
        }
        InnerBundleInfo bundleInfo;
        bundleInfo.SetKeyId(info.userId, keyId);
        if (!dataMgr->UpdateInnerBundleInfo(info)) {
            APP_LOGE("save keyId failed");
            continue;
        }
        APP_LOGI("OnRegenerateAppKey success for %{public}s", info.bundleName.c_str());
    }
}
} // AppExecFwk
} // OHOS
