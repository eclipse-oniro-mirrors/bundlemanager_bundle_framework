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

#include "security_audit_reporter.h"

#include <unordered_map>

#include "app_log_tag_wrapper.h"
#include "bundle_util.h"
#include "nlohmann/json.hpp"
#ifdef SECURITY_GUARD_ENABLE
#include "sg_collect_client.h"
#include "security_guard_error_code.h"
#endif

namespace OHOS {
namespace AppExecFwk {
namespace {
constexpr const char* SECURITY_AUDIT_VERSION = "1.0";

constexpr int64_t EVENT_ID_APP_INSTALL_INTERCEPTED = 0x18000100;
constexpr int64_t EVENT_ID_APP_UNINSTALL_INTERCEPTED = 0x18000101;
constexpr int64_t EVENT_ID_APP_UPDATE_INTERCEPTED = 0x18000102;
constexpr int64_t EVENT_ID_APP_RECOVER_INTERCEPTED = 0x18000103;

// fixed metadata values required by the security audit interface
constexpr const char* METADATA_VERSION = "";
constexpr const char* METADATA_DATE = "";
constexpr const char* METADATA_DEVICE_ID = "";
constexpr int32_t METADATA_USER_ID = 0;
constexpr int32_t METADATA_EVENT_TYPE = 0;
} // namespace

int64_t SecurityAuditReporter::GetEventId(BundleEventType bundleEventType)
{
    static const std::unordered_map<BundleEventType, int64_t> eventIdMap = {
        {BundleEventType::INSTALL, EVENT_ID_APP_INSTALL_INTERCEPTED},
        {BundleEventType::UNINSTALL, EVENT_ID_APP_UNINSTALL_INTERCEPTED},
        {BundleEventType::UPDATE, EVENT_ID_APP_UPDATE_INTERCEPTED},
        {BundleEventType::RECOVER, EVENT_ID_APP_RECOVER_INTERCEPTED},
    };
    auto it = eventIdMap.find(bundleEventType);
    return (it != eventIdMap.end()) ? it->second : EVENT_ID_APP_INSTALL_INTERCEPTED;
}

std::string SecurityAuditReporter::BuildContent(BundleEventType bundleEventType,
    const EventInfo &eventInfo)
{
    nlohmann::json content;
    content["bundleName"] = eventInfo.bundleName;
    content["callingBundleName"] = eventInfo.callingBundleName;
    content["callingUid"] = eventInfo.callingUid;
    // event time in milliseconds, convertible to UTC time
    content["timestamp_utc"] = BundleUtil::GetCurrentTimeMs();

    nlohmann::json metadata;
    metadata["version"] = METADATA_VERSION;
    metadata["date"] = METADATA_DATE;
    metadata["deviceId"] = METADATA_DEVICE_ID;
    metadata["userId"] = METADATA_USER_ID;
    metadata["eventType"] = METADATA_EVENT_TYPE;

    nlohmann::json contentJson;
    contentJson["content"] = content;
    contentJson["eventId"] = GetEventId(bundleEventType);
    contentJson["metadata"] = metadata;
    return contentJson.dump();
}

bool SecurityAuditReporter::Report(BundleEventType bundleEventType, const EventInfo& eventInfo)
{
#ifdef SECURITY_GUARD_ENABLE
    int64_t eventId = GetEventId(bundleEventType);
    std::string content = BuildContent(bundleEventType, eventInfo);
    auto auditInfo = std::make_shared<Security::SecurityGuard::EventInfo>(eventId, SECURITY_AUDIT_VERSION, content);

    int32_t ret = Security::SecurityGuard::NativeDataCollectKit::ReportSecurityInfoAsync(auditInfo);
    if (ret != Security::SecurityGuard::SUCCESS) {
        LOG_W(BMS_TAG_DEFAULT,
            "security audit report failed ret=%{public}d eventId=%{public}s bundle=%{public}s errCode=%{public}d "
            "userId=%{public}d callingUid=%{public}d",
            ret, std::to_string(eventId).c_str(), eventInfo.bundleName.c_str(), eventInfo.errCode,
            eventInfo.userId, eventInfo.callingUid);
        return false;
    }

    LOG_I(BMS_TAG_DEFAULT,
        "security audit reported eventId=%{public}s bundle=%{public}s errCode=%{public}d userId=%{public}d "
        "callingUid=%{public}d callingBundle=%{public}s eventType=%{public}d",
        std::to_string(eventId).c_str(), eventInfo.bundleName.c_str(), eventInfo.errCode, eventInfo.userId,
        eventInfo.callingUid, eventInfo.callingBundleName.c_str(),
        static_cast<int32_t>(bundleEventType));
    return true;
#else
    LOG_D(BMS_TAG_DEFAULT, "security guard not enabled, skip audit report bundle=%{public}s errCode=%{public}d",
        eventInfo.bundleName.c_str(), eventInfo.errCode);
    return false;
#endif
}
} // namespace AppExecFwk
} // namespace OHOS
