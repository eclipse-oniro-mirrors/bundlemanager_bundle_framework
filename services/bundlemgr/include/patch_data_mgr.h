/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#ifndef FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_PATCH_DATA_MGR_H
#define FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_PATCH_DATA_MGR_H

#include "patch_data_storage_rdb.h"
#include "inner_patch_info.h"

namespace OHOS {
namespace AppExecFwk {
class PatchDataMgr final {
public:
    static PatchDataMgr& GetInstance();
    /**
     * @brief Add new InnerPatchInfo.
     * @param bundleName Indicates the bundle name.
     * @param info Indicates the InnerBundleInfo object to be save.
     * @return Returns true if this function is successfully called; returns false otherwise.
     */
    bool AddInnerPatchInfo(const std::string &bundleName, const InnerPatchInfo &info);

    /**
     * @brief Get target InnerPatchInfo.
     * @param bundleName Indicates the bundle name.
     * @param info Indicates the InnerBundleInfo object to be save.
     * @return Returns true if this function is successfully called; returns false otherwise.
     */
    bool GetInnerPatchInfo(const std::string &bundleName, InnerPatchInfo &info) const;

    /**
     * @brief delete InnerPatchInfo.
     * @param bundleName Indicates the bundle name.
     * @return Returns true if this function is successfully called; returns false otherwise.
     */
    bool DeleteInnerPatchInfo(const std::string &bundleName);

    /**
     * @brief Process InnerPatchInfo.
     * @param bundleName Indicates the bundle name.
     * @param installSources Indicates the app install sources.
     * @param versionCode Indicates the app version.
     * @param type Indicates app patch type.
     * @param isPatch Indicates whether the app is an emergency patch module.
     * @return no return
     */
    void ProcessPatchInfo(const std::string &bundleName, const std::vector<std::string> &installSources,
        uint32_t versionCode, AppPatchType type, bool isPatch = false);

private:
    PatchDataMgr();
    ~PatchDataMgr();
    DISALLOW_COPY_AND_MOVE(PatchDataMgr);

    std::shared_ptr<PatchDataStorageRdb> patchDataStorage_;
};

}  // namespace AppExecFwk
}  // namespace OHOS
#endif  // FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_PATCH_DATA_MGR_H
