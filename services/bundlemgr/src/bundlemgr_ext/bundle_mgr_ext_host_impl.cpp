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

#include "bundle_mgr_ext_host_impl.h"

#include "app_log_tag_wrapper.h"
#include "bundle_permission_mgr.h"
#include "bms_extension_data_mgr.h"
#include "hitrace_meter.h"
#include "event_report.h"
#include "ipc_skeleton.h"

namespace OHOS {
namespace AppExecFwk {
BundleMgrExtHostImpl::BundleMgrExtHostImpl()
{
}

BundleMgrExtHostImpl::~BundleMgrExtHostImpl()
{
}

int32_t BundleMgrExtHostImpl::CallbackEnter([[maybe_unused]] uint32_t code)
{
    BundleMemoryGuard::SetBundleMemoryGuard();
    return ERR_NONE;
}

int32_t BundleMgrExtHostImpl::CallbackExit([[maybe_unused]] uint32_t code, [[maybe_unused]] int32_t result)
{
    BundleMemoryGuard::ClearBundleMemoryGuard();
    return ERR_NONE;
}

ErrCode BundleMgrExtHostImpl::GetBundleNamesForUidExt(const int32_t uid, std::vector<std::string> &bundleNames,
    int32_t &funcResult)
{
    HITRACE_METER_NAME_EX(HITRACE_LEVEL_INFO, HITRACE_TAG_APP, __PRETTY_FUNCTION__, nullptr);
    LOG_D(BMS_TAG_EXT, "start uid:%{public}d", uid);
    if (!BundlePermissionMgr::VerifyCallingPermissionForAll(Constants::PERMISSION_GET_BUNDLE_INFO_PRIVILEGED)) {
        funcResult = ERR_BUNDLE_MANAGER_PERMISSION_DENIED;
        return ERR_OK;
    }
    BmsExtensionDataMgr bmsExtensionDataMgr;
    ErrCode ret = bmsExtensionDataMgr.GetBundleNamesForUidExt(uid, bundleNames);
    if (ret != ERR_OK) {
        LOG_E(BMS_TAG_EXT, "uid:%{public}d err:%{public}d", uid, ret);
    }
    funcResult = ret;
    return ERR_OK;
}
} // AppExecFwk
} // OHOS