/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#ifndef FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_USER_LOCKED_EVENT_SUBSCRIBER_H
#define FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_USER_LOCKED_EVENT_SUBSCRIBER_H

#include <mutex>

#include "bundle_info.h"
#include "common_event_data.h"
#include "common_event_subscriber.h"
#include "ipc/create_dir_param.h"

namespace OHOS {
namespace AppExecFwk {
class BundleDataMgr;
class UserUnlockedEventSubscriber final : public EventFwk::CommonEventSubscriber {
public:
    explicit UserUnlockedEventSubscriber(const EventFwk::CommonEventSubscribeInfo &subscribeInfo);
    virtual ~UserUnlockedEventSubscriber();
    void OnReceiveEvent(const EventFwk::CommonEventData &data) override;

private:
    std::mutex mutex_;
    int32_t userId_ = 0;
};

class UpdateAppDataMgr {
public:
    static void UpdateAppDataDirSelinuxLabel(int32_t userId);
    // dual-mode: dedicated unlock rebuild pass that ONLY processes the other-mode (hidden)
    // variants recorded in tempBundleInfos_. Their OTA-time data dir creation failed the same
    // way on locked encrypted dirs, and the mode switch only swaps records between the two
    // maps (never creates dirs), so without this pass those apps would come up with missing
    // data dirs after a later mode switch. Runs the same dir set as the current-mode passes
    // inside UpdateAppDataDirSelinuxLabel; no-op on non-dual-mode devices (tempBundleInfos_
    // is never populated there). taskNum is the shared task number of the unlock rebuild so
    // every pass still honors the task cancellation (ReturnIfNewTask).
    static void UpdateTempModeAppDataDirs(int32_t userId, uint32_t taskNum);
    static void ProcessUpdateAppDataDir(
        int32_t userId, const std::vector<BundleInfo> &bundleInfos, const std::string &elDir);
    static void ProcessUpdateCloneDataDir(int32_t userId, const std::shared_ptr<BundleDataMgr> &dataMgr,
        bool toTempBundle = false);
    static void ProcessCloneBundleDirs(int32_t userId, const std::shared_ptr<BundleDataMgr> &dataMgr,
        bool toTempBundle = false);
    static void ProcessUpdateAppLogDir(const std::vector<BundleInfo> &bundleInfos, int32_t userId);
    static void ProcessFileManagerDir(const std::vector<BundleInfo> &bundleInfos, int32_t userId);
    static void ProcessExtensionDir(const BundleInfo &bundleInfo, std::vector<std::string> &dirs);
    static void ProcessPrintSericeDir(const BundleInfo &bundleInfo, bool &hasDriverExtension);
    static void ProcessNewBackupDir(const std::vector<BundleInfo> &bundleInfos, int32_t userId);
    static void CreateShareFilesSubDataDirs(const std::vector<BundleInfo> &bundleInfos, int32_t userId);
    static void DeleteUninstallTmpDirs(const std::set<int32_t>& userIds);
private:
    // Shared dir-pass implementations. toTempBundle routes the per-variant record fetches
    // (data groups, el5 clone/sandbox extras, U1 flag) to tempBundleInfos_ — the other-mode
    // variant's own record. Defaults to false (current-mode variants, the pre-dual-mode
    // behavior, so pre-existing callers/tests need no change); UpdateTempModeAppDataDirs
    // passes true (other-mode variants).
    static void ProcessUpdateAppDataDirInternal(
        int32_t userId, const std::vector<BundleInfo> &bundleInfos, const std::string &elDir,
        bool toTempBundle = false);
    static void ProcessUpdateAppLogDirInternal(const std::vector<BundleInfo> &bundleInfos, int32_t userId,
        bool toTempBundle = false);
    static void CheckPathAttribute(const std::string &path, const BundleInfo &bundleInfo, bool &isExist);
    static void CreateNewBackupDir(const BundleInfo &bundleInfo, int32_t userId);
    static bool CreateBundleDataDir(const BundleInfo &bundleInfo, int32_t userId, const std::string &elDir,
        bool toTempBundle = false);
    static bool CreateBundleLogDir(const BundleInfo &bundleInfo, int32_t userId);
    static bool CreateBundleCloudDir(const BundleInfo &bundleInfo, int32_t userId);
    static void CreateDataGroupDir(const BundleInfo &bundleInfo, int32_t userId, bool toTempBundle = false);
    static bool CreateEl5Dir(const CreateDirParam &createDirParam, bool toTempBundle = false);
    static std::vector<std::string> GetBundleDataDirs(const int32_t userId);
    static bool CheckU1EnableProcess(const BundleInfo &bundleInfo, bool toTempBundle = false);
};
}  // namespace AppExecFwk
}  // namespace OHOS
#endif // FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_USER_LOCKED_EVENT_SUBSCRIBER_H
