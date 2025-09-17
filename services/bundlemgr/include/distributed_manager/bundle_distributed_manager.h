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

#ifndef FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_DISTRIBUTED_MANAGER_BUNDLE_DISTRIBUTED_MANAGER_H
#define FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_DISTRIBUTED_MANAGER_BUNDLE_DISTRIBUTED_MANAGER_H

#include <shared_mutex>

#include "iremote_broker.h"
#include "query_rpc_id_params.h"
#include "rpc_id_result.h"
#include "serial_queue.h"
#include "target_ability_info.h"
#include "want.h"

namespace OHOS {
namespace AppExecFwk {
using namespace OHOS::AAFwk;
class BundleDistributedManager : public std::enable_shared_from_this<BundleDistributedManager> {
public:
    BundleDistributedManager();
    ~BundleDistributedManager();

    bool CheckAbilityEnableInstall(
        const Want &want, int32_t missionId, int32_t userId, const sptr<IRemoteObject> &callerToken);

    void OnQueryRpcIdFinished(const std::string &queryRpcIdResult);
private:
    bool ConvertTargetAbilityInfo(const Want &want, TargetAbilityInfo &targetAbilityInfo);
    bool QueryRpcIdByAbilityToServiceCenter(const TargetAbilityInfo &targetInfo);
    void SendCallbackRequest(int32_t resultCode, const std::string &transactId);
    void SendCallback(int32_t resultCode, const QueryRpcIdParams &queryRpcIdParams);
    int32_t ComparePcIdString(const Want &want, const RpcIdResult &rpcIdResult);
    void OutTimeMonitor(const std::string transactId);
    int GetTransactId() const
    {
        transactId_++;
        return transactId_.load();
    }
    mutable std::atomic<int> transactId_ = 0;
    std::shared_mutex mutex_;

    std::shared_ptr<SerialQueue> serialQueue_;
    std::map<std::string, QueryRpcIdParams> queryAbilityParamsMap_;
};
}  // namespace AppExecFwk
}  // namespace OHOS
#endif  // FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_DISTRIBUTED_MANAGER_BUNDLE_DISTRIBUTED_MANAGER_H