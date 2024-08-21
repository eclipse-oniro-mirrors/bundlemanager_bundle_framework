/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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
#ifndef FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_BUNDLE_AGING_MGR_H
#define FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_BUNDLE_AGING_MGR_H

#include <map>
#include <mutex>
#include <vector>

#include "aging/aging_constants.h"
#include "aging/aging_handler_chain.h"
#include "aging/aging_request.h"
#include "bundle_active_client.h"
#include "bundle_data_mgr.h"
#include "singleton.h"

namespace OHOS {
namespace AppExecFwk {
class BundleAgingMgr : public std::enable_shared_from_this<BundleAgingMgr> {
public:
    enum AgingTriggertype : uint8_t {
        PREIOD = 0,
        FREE_INSTALL = 1,
        UPDATE_REMOVABLE_FLAG = 2,
    };

public:
    BundleAgingMgr();
    ~BundleAgingMgr();

public:
    void Start(AgingTriggertype type);
    void InitAgingtTimer();

private:
    void InitAgingHandlerChain();
    void Process(const std::shared_ptr<BundleDataMgr> &dataMgr);
    bool CheckPrerequisite(AgingTriggertype type) const;
    void InitAgingTimerInterval();
    void InitAgingBatteryThresold();
    bool InitAgingRequest();
    bool ResetRequest();
    bool IsReachStartAgingThreshold();
    bool QueryBundleStatsInfoByInterval(std::vector<DeviceUsageStats::BundleActivePackageStats> &results);
    void ScheduleLoopTask();

private:
    std::mutex mutex_;
    bool running_ = false;
    AgingHandlerChain chain_;
    AgingRequest request_;
    int64_t agingTimerInterval_ = AgingConstants::DEFAULT_AGING_TIMER_INTERVAL;
    int64_t agingBatteryThresold_ = AgingConstants::DEFAULT_AGING_BATTERY_THRESHOLD;

private:
    static const uint32_t EVENT_AGING_NOW = 1;
};
}  //  namespace AppExecFwk
}  //  namespace OHOS
#endif  //  FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_BUNDLE_AGING_MGR_H