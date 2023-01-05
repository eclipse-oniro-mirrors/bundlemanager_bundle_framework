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
#include "aging/bundle_aging_mgr.h"

#include "account_helper.h"
#include "battery_srv_client.h"
#include "bundle_active_period_stats.h"
#include "bundle_mgr_service.h"
#include "bundle_util.h"
#include "display_power_mgr_client.h"
#include "parameter.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
const int32_t PERIOD_ANNUALLY = 4;

void StatisticsUsageStats(
    const std::vector<DeviceUsageStats::BundleActivePackageStats> &useStats,
    std::vector<DeviceUsageStats::BundleActivePackageStats> &results)
{
    for (const auto &useStat : useStats) {
        auto ret = std::any_of(results.begin(), results.end(),
            [&useStat](auto &result) {
                if (useStat.bundleName_ == result.bundleName_) {
                    result.startCount_ += useStat.startCount_;
                    if (result.lastTimeUsed_ < useStat.lastTimeUsed_) {
                        result.lastTimeUsed_ = useStat.lastTimeUsed_;
                    }

                    return true;
                }

                return false;
            });
        if (!ret) {
            results.emplace_back(useStat);
        }
    }
}
}

BundleAgingMgr::BundleAgingMgr()
{
    InitAgingHandlerChain();
    APP_LOGI("BundleAgingMgr is created.");
}

BundleAgingMgr::~BundleAgingMgr()
{
    APP_LOGI("BundleAgingMgr is destroyed");
}

void BundleAgingMgr::InitAgingRunner()
{
    auto agingRunner = EventRunner::Create(AgingConstants::AGING_THREAD);
    if (agingRunner == nullptr) {
        APP_LOGE("create aging runner failed");
        return;
    }

    SetEventRunner(agingRunner);
}

void BundleAgingMgr::InitAgingTimerInterval()
{
    char szTimerThresold[AgingConstants::THRESHOLD_VAL_LEN] = {0};
    int32_t ret = GetParameter(AgingConstants::SYSTEM_PARAM_AGING_TIMER_INTERVAL.c_str(), "", szTimerThresold,
        AgingConstants::THRESHOLD_VAL_LEN);
    APP_LOGD("ret is %{public}d, szTimerThresold is %{public}d", ret, atoi(szTimerThresold));
    if (ret <= 0) {
        APP_LOGD("GetParameter failed");
        return;
    }

    if (strcmp(szTimerThresold, "") != 0) {
        agingTimerInterval_ = atoi(szTimerThresold);
        APP_LOGD("BundleAgingMgr init aging timer success");
    }
}

void BundleAgingMgr::InitAgingBatteryThresold()
{
    char szBatteryThresold[AgingConstants::THRESHOLD_VAL_LEN] = {0};
    int32_t ret = GetParameter(AgingConstants::SYSTEM_PARAM_AGING_BATTER_THRESHOLD.c_str(), "", szBatteryThresold,
        AgingConstants::THRESHOLD_VAL_LEN);
    APP_LOGD("ret is %{public}d, szBatteryThresold is %{public}d", ret, atoi(szBatteryThresold));
    if (ret <= 0) {
        APP_LOGD("GetParameter failed");
        return;
    }

    if (strcmp(szBatteryThresold, "") != 0) {
        agingBatteryThresold_ = atoi(szBatteryThresold);
        APP_LOGD("BundleAgingMgr init battery threshold success");
    }
}

void BundleAgingMgr::InitAgingtTimer()
{
    InitAgingBatteryThresold();
    InitAgingTimerInterval();
    bool isEventStarted = SendEvent(InnerEvent::Get(EVENT_AGING_NOW), agingTimerInterval_);
    if (!isEventStarted) {
        APP_LOGE("faild to send event is not started");
        {
            std::lock_guard<std::mutex> lock(mutex_);
            running_ = false;
        }
    }
}

bool BundleAgingMgr::ResetRequest()
{
    auto dataMgr = OHOS::DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
    if (dataMgr == nullptr) {
        APP_LOGE("dataMgr is null");
        return false;
    }

    request_.ResetRequest();
    request_.SetTotalDataBytes(dataMgr->GetAllFreeInstallBundleSpaceSize());
    return true;
}

bool BundleAgingMgr::IsReachStartAgingThreshold()
{
    return request_.IsReachStartAgingThreshold();
}

bool BundleAgingMgr::QueryBundleStatsInfoByInterval(
    std::vector<DeviceUsageStats::BundleActivePackageStats> &results)
{
    auto dataMgr = OHOS::DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
    if (dataMgr == nullptr) {
        APP_LOGE("dataMgr is null");
        return false;
    }

    int64_t startTime = 0;
    int64_t endTime = AgingUtil::GetNowSysTimeMs();
    std::vector<DeviceUsageStats::BundleActivePackageStats> useStats;
    for (const auto &userId : dataMgr->GetAllUser()) {
        DeviceUsageStats::BundleActiveClient::GetInstance().QueryBundleStatsInfoByInterval(
            useStats, PERIOD_ANNUALLY, startTime, endTime, userId);
        StatisticsUsageStats(useStats, results);
        useStats.clear();
    }

    APP_LOGD("activeBundleRecord size %{public}zu", results.size());
    return !results.empty();
}

bool BundleAgingMgr::InitAgingRequest()
{
    auto dataMgr = OHOS::DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
    if (dataMgr == nullptr) {
        APP_LOGE("dataMgr is null");
        return false;
    }

    if (!ResetRequest()) {
        APP_LOGE("Reset Request failed");
        return false;
    }

    if (!IsReachStartAgingThreshold()) {
        APP_LOGI("Not reach agingThreshold and not need aging.");
        return false;
    }

    std::vector<DeviceUsageStats::BundleActivePackageStats> activeBundleRecord;
    if (!QueryBundleStatsInfoByInterval(activeBundleRecord)) {
        APP_LOGE("InitAgingRequest: can not get bundle active bundle record");
        return false;
    }

    for (const auto &item : dataMgr->GetAllInnerbundleInfos()) {
        if (!item.second.IsBundleRemovable()) {
            continue;
        }

        int64_t installTime = item.second.GetLastInstallationTime();
        auto bundleName = item.first;
        DeviceUsageStats::BundleActivePackageStats bundleRecord;
        bundleRecord.bundleName_ = bundleName;
        bundleRecord.lastTimeUsed_ = installTime;
        std::any_of(activeBundleRecord.begin(), activeBundleRecord.end(),
            [&bundleRecord](const auto &record) {
                if (record.bundleName_ == bundleRecord.bundleName_) {
                    bundleRecord = record;
                    return true;
                }

                return false;
            });
        APP_LOGD("bundle: %{public}s, lastTimeUsed: %{public}lld, startCount: %{public}d",
            bundleName.c_str(), bundleRecord.lastTimeUsed_, bundleRecord.startCount_);
        AgingBundleInfo agingBundleInfo(bundleName, bundleRecord.lastTimeUsed_, bundleRecord.startCount_);
        request_.AddAgingBundle(agingBundleInfo);
    }

    return request_.SortAgingBundles() > 0;
}

void BundleAgingMgr::Process(const std::shared_ptr<BundleDataMgr> &dataMgr)
{
    APP_LOGD("BundleAging begin to process.");
    if (InitAgingRequest()) {
        chain_.Process(request_);
    }

    {
        std::lock_guard<std::mutex> lock(mutex_);
        running_ = false;
    }

    APP_LOGD("BundleAgingMgr Process done");
}

void BundleAgingMgr::Start(AgingTriggertype type)
{
    APP_LOGD("aging start, AgingTriggertype: %{public}d", type);
    if (!CheckPrerequisite(type)) {
        APP_LOGE("BundleAgingMgr aging Prerequisite is not satisfied");
        return;
    }

    auto dataMgr = OHOS::DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
    if (dataMgr == nullptr) {
        APP_LOGE("dataMgr is null");
        return;
    }

    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (running_) {
            APP_LOGD("BundleAgingMgr is running, no need to start is again");
            return;
        }
        running_ = true;
    }

    auto task = [&, dataMgr]() { Process(dataMgr); };
    bool isEventStarted = SendEvent(InnerEvent::Get(task));
    if (!isEventStarted) {
        APP_LOGE("BundleAgingMgr event is not started.");
        {
            std::lock_guard<std::mutex> lock(mutex_);
            running_ = false;
        }
    } else {
        APP_LOGD("BundleAgingMgr schedule process done");
    }
}

bool BundleAgingMgr::CheckPrerequisite(AgingTriggertype type) const
{
    if (type != AgingTriggertype::PREIOD) {
        return true;
    }

    DisplayPowerMgr::DisplayState state = DisplayPowerMgr::DisplayPowerMgrClient::GetInstance().GetDisplayState();
    if (state == DisplayPowerMgr::DisplayState::DISPLAY_ON) {
        APP_LOGD("current Displaystate is DisplayState::DISPLAY_ON");
        return false;
    }

    int32_t currentBatteryCap = OHOS::PowerMgr::BatterySrvClient::GetInstance().GetCapacity();
    APP_LOGD("current GetCapacity is %{public}d agingBatteryThresold: %{public}" PRId64,
        currentBatteryCap, agingBatteryThresold_);
    return currentBatteryCap > agingBatteryThresold_;
}

void BundleAgingMgr::ProcessEvent(const InnerEvent::Pointer &event)
{
    uint32_t eventId = event->GetInnerEventId();
    APP_LOGD("BundleAgingMgr process event : %{public}u", eventId);
    switch (eventId) {
        case EVENT_AGING_NOW:
            APP_LOGD("BundleAgingMgr timer expire, run aging now.");
            Start(AgingTriggertype::PREIOD);
            SendEvent(eventId, 0, agingTimerInterval_);
            APP_LOGD("BundleAginMgr reschedule time.");
            break;
        default:
            APP_LOGD("BundleAgingMgr invalid Event %{public}d.", eventId);
            break;
    }
}

void BundleAgingMgr::InitAgingHandlerChain()
{
    chain_ = AgingHandlerChain();
    chain_.AddHandler(std::make_shared<Over30DaysUnusedBundleAgingHandler>());
    chain_.AddHandler(std::make_shared<Over20DaysUnusedBundleAgingHandler>());
    chain_.AddHandler(std::make_shared<Over10DaysUnusedBundleAgingHandler>());
    chain_.AddHandler(std::make_shared<BundleDataSizeAgingHandler>());
}
}  //  namespace AppExecFwk
}  //  namespace OHOS
