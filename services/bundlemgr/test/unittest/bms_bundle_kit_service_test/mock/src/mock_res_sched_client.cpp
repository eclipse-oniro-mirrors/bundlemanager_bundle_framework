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

#include "mock_res_sched_client.h"

#include <mutex>
#include <unordered_map>

#include "res_sched_client.h"

namespace {
constexpr const char* EXT_TYPE_KEY = "extType";
std::mutex g_mockResSchedMutex;
std::vector<OHOS::ResourceSchedule::MockResSchedReport> g_mockResSchedReports;
} // namespace

namespace OHOS {
namespace ResourceSchedule {

// Interpose ResSchedClient::ReportData: GetInstance stays in libressched_client.so,
// while calls from the test binary are recorded here instead of being sent via IPC.
void ResSchedClient::ReportData(uint32_t resType, int64_t value,
    const std::unordered_map<std::string, std::string>& mapPayload)
{
    MockResSchedReport report;
    report.resType = resType;
    report.value = value;
    auto it = mapPayload.find(EXT_TYPE_KEY);
    if (it != mapPayload.end()) {
        report.extType = it->second;
    }
    std::lock_guard<std::mutex> lock(g_mockResSchedMutex);
    g_mockResSchedReports.emplace_back(report);
}

void ResetMockResSchedReports()
{
    std::lock_guard<std::mutex> lock(g_mockResSchedMutex);
    g_mockResSchedReports.clear();
}

std::vector<MockResSchedReport> GetMockResSchedReports()
{
    std::lock_guard<std::mutex> lock(g_mockResSchedMutex);
    return g_mockResSchedReports;
}

} // namespace ResourceSchedule
} // namespace OHOS
