/*
 * Copyright (c) 2023-2024 Huawei Device Co., Ltd.
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

#ifndef FOUNDATION_BUNDLE_FRAMEWORK_AOT_AOT_HANDLER
#define FOUNDATION_BUNDLE_FRAMEWORK_AOT_AOT_HANDLER

#include <mutex>
#include <optional>
#include <string>
#include <unordered_map>

#include "aot/aot_args.h"
#include "bundle_mgr_service.h"
#include "event_report.h"
#include "inner_bundle_info.h"
#include "nocopyable.h"
#include "serial_queue.h"

namespace OHOS {
namespace AppExecFwk {
class AOTHandler final {
public:
    static AOTHandler& GetInstance();
    void HandleInstall(const std::unordered_map<std::string, InnerBundleInfo> &infos) const;
    void HandleOTA();
    void HandleIdle() const;
    ErrCode HandleCompile(const std::string &bundleName, const std::string &compileMode, bool isAllBundle,
        std::vector<std::string> &compileResults) const;
    void HandleResetAOT(const std::string &bundleName, bool isAllBundle) const;
    ErrCode HandleCopyAp(const std::string &bundleName, bool isAllBundle, std::vector<std::string> &results) const;
private:
    AOTHandler();
    ~AOTHandler() = default;
    DISALLOW_COPY_AND_MOVE(AOTHandler);

    ErrCode MkApDestDirIfNotExist() const;
    void CopyApWithBundle(const std::string &bundleName, const BundleInfo &bundleInfo,
        const int32_t userId, std::vector<std::string> &results) const;
    std::string GetSouceAp(const std::string &mergedAp, const std::string &rtAp) const;
    bool IsSupportARM64() const;
    std::string GetArkProfilePath(const std::string &bundleName, const std::string &moduleName) const;
    std::optional<AOTArgs> BuildAOTArgs(
        const InnerBundleInfo &info, const std::string &moduleName, const std::string &compileMode) const;
    void HandleInstallWithSingleHap(const InnerBundleInfo &info, const std::string &compileMode) const;
    ErrCode HandleCompileWithSingleHap(
    const InnerBundleInfo &info, const std::string &moduleName, const std::string &compileMode) const;
    EventInfo HandleCompileWithBundle(const std::string &bundleName, const std::string &compileMode,
        std::shared_ptr<BundleDataMgr> dataMgr) const;
    ErrCode HandleCompileBundles(const std::vector<std::string> &bundleNames, const std::string &compileMode,
        std::shared_ptr<BundleDataMgr> &dataMgr, std::vector<std::string> &compileResults) const;
    ErrCode HandleCompileModules(const std::vector<std::string> &moduleNames, const std::string &compileMode,
        InnerBundleInfo &info, std::string &compileResult) const;
    void ClearArkCacheDir() const;
    void ResetAOTFlags() const;
    void HandleIdleWithSingleHap(
        const InnerBundleInfo &info, const std::string &moduleName, const std::string &compileMode) const;
    bool CheckDeviceState() const;
    ErrCode AOTInternal(std::optional<AOTArgs> aotArgs, uint32_t versionCode) const;
    void HandleOTACompile();
    void BeforeOTACompile();
    void OTACompile() const;
    void OTACompileInternal() const;
    bool GetOTACompileList(std::vector<std::string> &bundleNames) const;
    bool GetUserBehaviourAppList(std::vector<std::string> &bundleNames, int32_t size) const;
    bool IsOTACompileSwitchOn() const;
    void ReportSysEvent(const std::map<std::string, EventInfo> &sysEventMap) const;
private:
    mutable std::mutex executeMutex_;
    mutable std::mutex idleMutex_;
    mutable std::mutex compileMutex_;
    std::atomic<bool> OTACompileDeadline_ { false };
    std::shared_ptr<SerialQueue> serialQueue_;
};
}  // namespace AppExecFwk
}  // namespace OHOS
#endif  // FOUNDATION_BUNDLE_FRAMEWORK_AOT_AOT_HANDLER
