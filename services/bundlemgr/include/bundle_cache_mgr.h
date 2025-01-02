/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#ifndef FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_BUNDLE_CACHE_MGR_H
#define FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_BUNDLE_CACHE_MGR_H

#include <mutex>
#include <vector>

#include "account_helper.h"
#include "app_log_tag_wrapper.h"
#include "bundle_data_mgr.h"
#include "inner_bundle_clone_common.h"
#include "install_param.h"
#include "installd_client.h"
#include "ipc_skeleton.h"
#include "process_cache_callback_interface.h"

namespace OHOS {
namespace AppExecFwk {
class BundleCacheMgr {
public:
    static std::vector<std::string> GetBundleCachePath(const std::string &bundleName, const int32_t userId,
        const int32_t appIndex, const std::vector<std::string> &moduleNameList);
    /**
     * @brief get cache size of all bundle.
     * @param validBundles indicates the tuple of <bundleName, moduleNames, appCloneIndexes>
     * @param cacheStat indicates the result of all bundle cache size
     * @return Returns ERR_OK if get all bundle cache size; returns errCode otherwise.
     */
    static void GetBundleCacheSize(const std::vector<std::tuple<std::string,
        std::vector<std::string>, std::vector<int32_t>>> &validBundles,
        const int32_t userId, uint64_t &cacheStat);
    static ErrCode GetAllBundleCacheStat(const sptr<IProcessCacheCallback> processCacheCallback);
};
} // AppExecFwk
} // OHOS

#endif // FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_BUNDLE_CACHE_MGR_H