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

#ifndef FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_SECURITY_AUDIT_REPORTER_H
#define FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_SECURITY_AUDIT_REPORTER_H

#include <cstdint>
#include <string>

#include "event_report.h"

namespace OHOS {
namespace AppExecFwk {
class SecurityAuditReporter {
public:
    /**
     * @brief Report an intercepted event to the security audit channel via
     *        SecurityGuard NativeDataCollectKit::ReportSecurityInfoAsync.
     *        The content JSON contains three entries: "content"
     *        (bundleName/callingBundleName/callingUid/timestamp_utc in ms),
     *        "eventId" and a fixed "metadata" object.
     *        Best-effort: any failure only logs a warning and returns false
     *        without affecting the caller.
     * @param bundleEventType The bundle event type (INSTALL/UNINSTALL/UPDATE/RECOVER).
     * @param eventInfo The event info containing the intercepted bundle info.
     * @return true if reported successfully, false otherwise.
     */
    static bool Report(BundleEventType bundleEventType, const EventInfo& eventInfo);

private:
    SecurityAuditReporter() = delete;
    static int64_t GetEventId(BundleEventType bundleEventType);
    static std::string BuildContent(BundleEventType bundleEventType, const EventInfo& eventInfo);
};
} // namespace AppExecFwk
} // namespace OHOS

#endif // FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_SECURITY_AUDIT_REPORTER_H
