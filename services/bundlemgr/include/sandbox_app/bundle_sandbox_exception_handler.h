/*
 * Copyright (c) 2022-2024 Huawei Device Co., Ltd.
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

#ifndef FOUNDATION_APPEXECFWK_SERVICES_BUNDLE_SANDBOX_EXCEPTION_HANDLE_H
#define FOUNDATION_APPEXECFWK_SERVICES_BUNDLE_SANDBOX_EXCEPTION_HANDLE_H

#include "bundle_data_storage_interface.h"
#include "common_event_subscriber.h"

namespace OHOS {
namespace AppExecFwk {
using namespace OHOS::EventFwk;

class BundleMgrCommonEventSubscriber final : public CommonEventSubscriber {
public:
    BundleMgrCommonEventSubscriber(const CommonEventSubscribeInfo &subscribeInfo,
        const std::map<int32_t, std::vector<std::string>> &sandboxDirs);
    virtual ~BundleMgrCommonEventSubscriber() {};
    virtual void OnReceiveEvent(const CommonEventData &data);

private:
    static void RemoveSandboxDataDir(int32_t userId,
        const std::map<int32_t, std::vector<std::string>> &toDeleteSandboxDir);

    std::map<int32_t, std::vector<std::string>> toDeleteSandboxDir_;
};

class BundleSandboxExceptionHandler final {
public:
    explicit BundleSandboxExceptionHandler(const std::shared_ptr<IBundleDataStorage> &dataStorage);
    ~BundleSandboxExceptionHandler();

    /**
     * @brief to remove the sandbox data dir when the bms service inits
     * @param info indicates the inner bundleInfo of the application.
     */
    void RemoveSandboxApp(InnerBundleInfo &info);

private:
    void RemoveTokenIdAndKeepSandboxDir(const std::string &bundleName,
        const std::vector<SandboxAppPersistentInfo> &sandboxPersistentInfo, const InnerBundleInfo &info);
    void UpdateBundleInfoToStorage(const InnerBundleInfo &info);
    void KeepSandboxDirs(const std::string &bundleName, int32_t appIndex, int32_t userId);
    void RemoveDataDir();
    void ListeningUserUnlocked();

    std::weak_ptr<IBundleDataStorage> dataStorage_;
    std::map<int32_t, std::vector<std::string>> sandboxDirs_;
};
}  // namespace AppExecFwk
}  // namespace OHOS
#endif // FOUNDATION_APPEXECFWK_SERVICES_BUNDLE_SANDBOX_EXCEPTION_HANDLE_H
