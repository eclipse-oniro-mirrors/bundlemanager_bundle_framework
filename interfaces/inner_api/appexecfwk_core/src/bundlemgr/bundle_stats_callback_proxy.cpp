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

#include "bundle_stats_callback_proxy.h"

#include "app_log_wrapper.h"
#include "app_log_tag_wrapper.h"
#include "bundle_framework_core_ipc_interface_code.h"
#include "ipc_types.h"
#include "parcel.h"

namespace OHOS {
namespace AppExecFwk {
BundleStatsCallbackProxy::BundleStatsCallbackProxy(const sptr<IRemoteObject> &object)
    : IRemoteProxy<IBundleStatsCallback>(object)
{
    LOG_D(BMS_TAG_QUERY, "create bundle stats callback proxy instance");
}

BundleStatsCallbackProxy::~BundleStatsCallbackProxy()
{
    LOG_D(BMS_TAG_QUERY, "destroy bundle stats callback proxy instance");
}

void BundleStatsCallbackProxy::OnGetBundleStatsFinished(int32_t errCode, const std::vector<int64_t> &bundleStats)
{
    LOG_D(BMS_TAG_QUERY, "bundle stats result %{public}d", errCode);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    if (!data.WriteInterfaceToken(BundleStatsCallbackProxy::GetDescriptor())) {
        LOG_E(BMS_TAG_QUERY, "fail to OnGetBundleStatsFinished due to write MessageParcel fail");
        return;
    }

    if (!data.WriteInt32(errCode)) {
        LOG_E(BMS_TAG_QUERY, "fail to call OnGetBundleStatsFinished, for write errCode failed");
        return;
    }

    if (!data.WriteInt64Vector(bundleStats)) {
        LOG_E(BMS_TAG_QUERY, "fail to call OnGetBundleStatsFinished, for write bundleStats failed");
        return;
    }

    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        LOG_E(BMS_TAG_QUERY, "fail to call OnGetBundleStatsFinished, for Remote() is nullptr");
        return;
    }

    int32_t ret = remote->SendRequest(
        static_cast<int32_t>(BundleStatsCallbackInterfaceCode::ON_GET_BUNDLE_STATS_CALLBACK),
        data, reply, option);
    if (ret != NO_ERROR) {
        LOG_W(BMS_TAG_QUERY, "call OnGetBundleStatsFinished fail, for transact failed, error code: %{public}d", ret);
    }
}
}  // namespace AppExecFwk
}  // namespace OHOS
