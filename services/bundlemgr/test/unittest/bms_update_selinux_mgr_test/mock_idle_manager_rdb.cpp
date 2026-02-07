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

// Mock implementation of IdleManagerRdb for testing
// This file replaces the real idle_manager_rdb.cpp in test builds

#include "idle_manager_rdb.h"
#include "app_log_wrapper.h"

namespace OHOS {
namespace AppExecFwk {

// Global test control variables - used to control mock behavior
namespace {
    ErrCode g_getAllBundleResult = ERR_OK;
    std::vector<BundleOptionInfo> g_testBundles;
    ErrCode g_addBundlesResult = ERR_OK;
    ErrCode g_addBundleResult = ERR_OK;
    ErrCode g_deleteBundleResult = ERR_OK;
    ErrCode g_deleteBundleByUserResult = ERR_OK;
}

// Global test control functions (not part of IdleManagerRdb class)
void SetGetAllBundleResultForTest(ErrCode ret)
{
    g_getAllBundleResult = ret;
}

void SetBundlesForTest(const std::vector<BundleOptionInfo> &bundles)
{
    g_testBundles = bundles;
}

void SetAddBundlesResultForTest(ErrCode ret)
{
    g_addBundlesResult = ret;
}

void SetAddBundleResultForTest(ErrCode ret)
{
    g_addBundleResult = ret;
}

void SetDeleteBundleResultForTest(ErrCode ret)
{
    g_deleteBundleResult = ret;
    g_deleteBundleByUserResult = ret;
}

void ClearBundlesForTest()
{
    g_testBundles.clear();
}

// Mock implementation of IdleManagerRdb methods
IdleManagerRdb::IdleManagerRdb()
{
    APP_LOGI("IdleManagerRdb (Mock) created");
}

IdleManagerRdb::~IdleManagerRdb()
{
    APP_LOGI("IdleManagerRdb (Mock) destroyed");
}

ErrCode IdleManagerRdb::AddBundles(const std::vector<BundleOptionInfo> &bundleOptionInfos)
{
    APP_LOGI("IdleManagerRdb::AddBundles count=%{public}zu", bundleOptionInfos.size());
    return g_addBundlesResult;
}

ErrCode IdleManagerRdb::AddBundle(const BundleOptionInfo &bundleOptionInfo)
{
    APP_LOGI("IdleManagerRdb::AddBundle bundle=%{public}s", bundleOptionInfo.bundleName.c_str());
    return g_addBundleResult;
}

ErrCode IdleManagerRdb::DeleteBundle(const BundleOptionInfo &bundleOptionInfo)
{
    APP_LOGI("IdleManagerRdb::DeleteBundle bundle=%{public}s", bundleOptionInfo.bundleName.c_str());
    return g_deleteBundleResult;
}

ErrCode IdleManagerRdb::DeleteBundle(const int32_t userId)
{
    APP_LOGI("IdleManagerRdb::DeleteBundle userId=%{public}d", userId);
    return g_deleteBundleByUserResult;
}

ErrCode IdleManagerRdb::GetAllBundle(const int32_t userId, std::vector<BundleOptionInfo> &bundleOptionInfos)
{
    APP_LOGI("IdleManagerRdb::GetAllBundle userId=%{public}d", userId);
    if (g_getAllBundleResult != ERR_OK) {
        APP_LOGE("IdleManagerRdb::GetAllBundle returning error %{public}d", g_getAllBundleResult);
        return g_getAllBundleResult;
    }
    bundleOptionInfos = g_testBundles;
    APP_LOGI("IdleManagerRdb::GetAllBundle returning %{public}zu bundles", bundleOptionInfos.size());
    return ERR_OK;
}

bool IdleManagerRdb::ConvertToBundleOptionInfo(const std::shared_ptr<NativeRdb::ResultSet> &absSharedResultSet,
    BundleOptionInfo &bundleOptionInfo)
{
    // Mock implementation - not used in tests
    return false;
}

} // namespace AppExecFwk
} // namespace OHOS
