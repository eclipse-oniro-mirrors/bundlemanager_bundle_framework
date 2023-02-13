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

#ifndef FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_BUNDLE_OVERLAY_DATA_MANAGER_H
#define FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_BUNDLE_OVERLAY_DATA_MANAGER_H

#include "bundle_data_mgr.h"
#include "singleton.h"

namespace OHOS {
namespace AppExecFwk {
class OverlayDataMgr final : public DelayedSingleton<OverlayDataMgr> {
public:
    OverlayDataMgr() = default;
    virtual ~OverlayDataMgr() = default;

    bool IsExistedNonOverlayHap(const std::string &bundleName);

    ErrCode UpdateOverlayInfo(const InnerBundleInfo &newInfo, InnerBundleInfo &oldInfo);

    ErrCode UpdateInternalOverlayInfo(const InnerBundleInfo &newInfo, InnerBundleInfo &oldInfo) const;

    ErrCode UpdateExternalOverlayInfo(const InnerBundleInfo &newInfo);

    ErrCode BuildOverlayConnection(const InnerBundleInfo &newInfo, InnerBundleInfo &oldInfo);

    ErrCode GetBundleDir(const std::string &moduleHapPath, std::string &bundleDir) const;

    ErrCode RemoveOverlayModuleConnection(const InnerBundleInfo &newInfo, InnerBundleInfo &oldInfo);

    void RemoveOverlayBundleInfo(const std::string &targetBundleName, const std::string &bundleName);

    void RemoveOverlayModuleInfo(const std::string &bundleName,
        const std::string &modulePackage, InnerBundleInfo &oldInfo);

    void BuildExternalOverlayConnection(const std::string &moduleName, InnerBundleInfo &oldInfo);

    void BuildInternalOverlayConnection(const std::string &moduleName, InnerBundleInfo &oldInfo);

    bool GetOverlayInnerBundleInfo(const std::string &bundleName, InnerBundleInfo &info);

    void EnableOverlayBundle(const std::string &bundleName);

    ErrCode GetAllOverlayModuleInfo(const std::string &bundleName, std::vector<OverlayModuleInfo> &overlayModuleInfos,
        int32_t userId);

    ErrCode GetOverlayModuleInfo(const std::string &bundleName, const std::string &moduleName,
        OverlayModuleInfo &overlayModuleInfo, int32_t userId);

    ErrCode GetOverlayBundleInfoForTarget(const std::string &targetBundleName,
        std::vector<OverlayBundleInfo> &overlayBundleInfo, int32_t userId);

    ErrCode GetOverlayModuleInfoForTarget(const std::string &targetBundleName, const std::string &targetModuleName,
        std::vector<OverlayModuleInfo> &overlayModuleInfo, int32_t userId);

private:
    ErrCode GetBundleDataMgr();

    std::shared_ptr<BundleDataMgr> dataMgr_ = nullptr;
};
} // AppExecFwk
} // OHOS
#endif // FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_BUNDLE_OVERLAY_DATA_MANAGER_H