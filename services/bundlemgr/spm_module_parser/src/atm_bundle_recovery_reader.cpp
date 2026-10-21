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

#include "atm_bundle_recovery_info.h"

#include <iterator>
#include <map>
#include <memory>
#include "accesstoken_kit.h"
#include "app_log_tag_wrapper.h"
#include "appexecfwk_errors.h"
#include "atm_recovery_record_decoder.h"
#include "read_only_installed_bundle_store.h"
#include "token_setproc.h"

namespace OHOS::AppExecFwk {
namespace AccessToken = OHOS::Security::AccessToken;

namespace {
using namespace AtmRecovery;

AtmBundleRecoveryResult ReadRecoveryInfo()
{
    ReadOnlyInstalledBundleStore store;
    std::map<std::string, std::string> records;
    if (!store.Open() || !store.QueryAllData(records)) {
        LOG_NOFUNC_E(BMS_TAG_QUERY, "ATM recovery: cannot read installed records");
        return {ERR_APPEXECFWK_DB_GET_DATA_ERROR, {}};
    }
    AtmBundleRecoveryResult result;
    size_t normalRecordCount = 0;
    for (const auto &[key, value] : records) {
        std::vector<AtmBundleRecoveryInfo> infos;
        if (!ParseAtmRecoveryRecord(key, value, infos)) {
            continue;
        }
        result.infos.insert(result.infos.end(), std::make_move_iterator(infos.begin()),
            std::make_move_iterator(infos.end()));
        ++normalRecordCount;
    }
    if (!records.empty() && normalRecordCount == 0) {
        LOG_NOFUNC_E(BMS_TAG_QUERY, "ATM recovery: no complete result");
        return {ERR_APPEXECFWK_DB_GET_DATA_ERROR, {}};
    }
    if (normalRecordCount < records.size()) {
        LOG_NOFUNC_W(BMS_TAG_QUERY, "ATM recovery: skipped %{public}zu invalid records",
            records.size() - normalRecordCount);
    }
    return result;
}
} // namespace

AtmBundleRecoveryResult QueryAtmBundleRecoveryInfo()
{
    const auto tokenId = static_cast<AccessToken::AccessTokenID>(GetSelfTokenID());
    if (tokenId == 0 || AccessToken::AccessTokenKit::VerifyAccessToken(tokenId,
        "ohos.permission.GET_BUNDLE_INFO_PRIVILEGED") != AccessToken::PermissionState::PERMISSION_GRANTED) {
        LOG_NOFUNC_W(BMS_TAG_QUERY, "ATM recovery: permission unavailable or denied");
        return {ERR_APPEXECFWK_PERMISSION_DENIED, {}};
    }
    return ReadRecoveryInfo();
}
} // namespace OHOS::AppExecFwk
