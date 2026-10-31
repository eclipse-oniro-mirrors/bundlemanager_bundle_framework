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

#ifndef FOUNDATION_BUNDLE_FRAMEWORK_ATM_RECOVERY_RECORD_DECODER_H
#define FOUNDATION_BUNDLE_FRAMEWORK_ATM_RECOVERY_RECORD_DECODER_H

#include "atm_bundle_recovery_info.h"

namespace OHOS::AppExecFwk::AtmRecovery {
// Parse one installed_bundle record. Invalid data returns false with an empty output.
__attribute__((visibility("hidden"))) bool ParseAtmRecoveryRecord(const std::string &key,
    const std::string &value, std::vector<AtmBundleRecoveryInfo> &infos);
// Parse one uninstall_bundle_info record. Invalid data returns false with an empty output.
__attribute__((visibility("hidden"))) bool ParseUninstallRecord(const std::string &bundleName,
    const std::string &value, std::vector<AtmBundleRecoveryInfo> &infos);
} // namespace OHOS::AppExecFwk::AtmRecovery
#endif
