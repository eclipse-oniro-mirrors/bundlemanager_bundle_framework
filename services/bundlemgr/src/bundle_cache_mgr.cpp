/*
 * Copyright (c) 2024-2026 Huawei Device Co., Ltd.
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

#include "app_log_tag_wrapper.h"
#include "bundle_cache_mgr.h"

#include <cinttypes>
#include "bundle_mgr_service.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
constexpr int32_t INVALID_APP_INDEX = 0;
constexpr size_t INDEX_BUNDLE_NAME = 0;
constexpr size_t INDEX_MODULE_NAMES = 1;
constexpr size_t INDEX_CLONE_APP_INDEX = 2;
constexpr int64_t TOTAL_TIMEOUT_MS = 60000;
}

std::vector<std::string> BundleCacheMgr::GetBundleCachePath(const std::string &bundleName,
    const int32_t userId, const int32_t appIndex, const std::vector<std::string> &moduleNameList)
{
    std::string bundleNameDir = bundleName;
    std::vector<std::string> cachePaths;
    if (appIndex < INVALID_APP_INDEX) {
        return cachePaths;
    }
    if (appIndex > 0) {
        bundleNameDir = BundleCloneCommonHelper::GetCloneDataDir(bundleName, appIndex);
    }
    
    std::string elBase;
    for (const auto &el : ServiceConstants::FULL_BUNDLE_EL) {
        elBase = std::string(ServiceConstants::BUNDLE_APP_DATA_BASE_DIR) + el + ServiceConstants::PATH_SEPARATOR +
            std::to_string(userId) + ServiceConstants::BASE + bundleNameDir + ServiceConstants::PATH_SEPARATOR;
        std::string baseCachePath = elBase + Constants::CACHE_DIR;
        cachePaths.emplace_back(baseCachePath);

        if (ServiceConstants::BUNDLE_EL[1] == el) {
            baseCachePath = std::string(ServiceConstants::BUNDLE_APP_DATA_BASE_DIR) + el +
                ServiceConstants::PATH_SEPARATOR + std::to_string(userId) + ServiceConstants::SHAREFILES +
                bundleNameDir + ServiceConstants::PATH_SEPARATOR + Constants::CACHE_DIR;
            cachePaths.emplace_back(baseCachePath);
        }
        for (const auto &moduleName : moduleNameList) {
            std::string moduleCachePath = elBase + ServiceConstants::HAPS + moduleName +
                ServiceConstants::PATH_SEPARATOR + Constants::CACHE_DIR;
            cachePaths.emplace_back(moduleCachePath);
            if (ServiceConstants::BUNDLE_EL[1] == el) {
                moduleCachePath = std::string(ServiceConstants::BUNDLE_APP_DATA_BASE_DIR) + el +
                    ServiceConstants::PATH_SEPARATOR + std::to_string(userId) + ServiceConstants::SHAREFILES +
                    bundleNameDir + ServiceConstants::HAPS + moduleName + ServiceConstants::PATH_SEPARATOR +
                    Constants::CACHE_DIR;
                cachePaths.emplace_back(moduleCachePath);
            }
        }
    }
    return cachePaths;
}

void BundleCacheMgr::GetBundleCacheSize(const std::vector<std::tuple<std::string,
    std::vector<std::string>, std::vector<int32_t>>> &validBundles, const int32_t userId,
    uint64_t &cacheStat)
{
    auto startTime = std::chrono::steady_clock::now();
    for (const auto &item : validBundles) {
        std::string bundleName = std::get<INDEX_BUNDLE_NAME>(item);
        std::vector<std::string> moduleNames = std::get<INDEX_MODULE_NAMES>(item);
        std::vector<int32_t> allCloneAppIndex = std::get<INDEX_CLONE_APP_INDEX>(item);
        for (const auto &appIndex : allCloneAppIndex) {
            // Calculate the remaining timeout time
            auto currentTime = std::chrono::steady_clock::now();
            auto elapsedTime = std::chrono::duration_cast<std::chrono::milliseconds>(currentTime - startTime).count();
            auto remainingTime = TOTAL_TIMEOUT_MS - elapsedTime;
            if (remainingTime <= 0) {
                APP_LOGW("timeout");
                return;
            }
            std::vector<std::string> cachePaths = GetBundleCachePath(bundleName, userId, appIndex, moduleNames);
            int64_t cacheSize = 0;
            
            // Transfer remaining time to GetDiskUsageFromPath
            ErrCode ret = InstalldClient::GetInstance()->GetDiskUsageFromPath(cachePaths, cacheSize, remainingTime);
            if (ret != ERR_OK) {
                APP_LOGW("failed for %{public}s", bundleName.c_str());
                continue;
            }
            APP_LOGD("BundleCache stat: %{public}" PRId64 " bundlename: %{public}s",
                cacheSize, bundleName.c_str());
            cacheStat += static_cast<uint64_t>(cacheSize);
        }
    }
    return;
}

void BundleCacheMgr::GetBundleCacheSizeByAppIndex(const std::string &bundleName, int32_t userId,
    int32_t appIndex, const std::vector<std::string> &moduleNames, uint64_t &cacheStat)
{
    std::vector<std::string> cachePaths = GetBundleCachePath(bundleName, userId, appIndex, moduleNames);
    int64_t cacheSize = 0;
    ErrCode ret = InstalldClient::GetInstance()->GetDiskUsageFromPath(cachePaths, cacheSize);
    if (ret != ERR_OK) {
        APP_LOGW_NOFUNC("BundleCache failed for %{public}s", bundleName.c_str());
        return;
    }
    LOG_NOFUNC_D(BMS_TAG_INSTALLER, "BundleCache stat: %{public}" PRId64 " bundlename: %{public}s",
        cacheSize, bundleName.c_str());
    cacheStat += static_cast<uint64_t>(cacheSize);
    return;
}

ErrCode BundleCacheMgr::GetBundleInodeCount(int32_t uid, uint64_t &inodeCount)
{
    if (uid < 0) {
        inodeCount = 0;
        APP_LOGE_NOFUNC("Invalid uid: %{public}d", uid);
        return ERR_BUNDLE_MANAGER_INVALID_UID;
    }

    uint64_t totalInodeCount = 0;
    ErrCode ret = InstalldClient::GetInstance()->GetBundleInodeCount(uid, totalInodeCount);
    if (ret != ERR_OK) {
        APP_LOGE_NOFUNC("InodeCount failed for uid %{public}d", uid);
        return ret;
    }

    inodeCount = totalInodeCount;
    LOG_NOFUNC_D(BMS_TAG_INSTALLER, "succeeded, uid: %{public}d, inodeCount: %{public}llu",
        uid, inodeCount);

    return ERR_OK;
}

ErrCode BundleCacheMgr::GetAllBundleCacheStat(const sptr<IProcessCacheCallback> processCacheCallback)
{
    APP_LOGI("start");
    auto dataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
    if (dataMgr == nullptr) {
        APP_LOGE("GetAllBundleCacheStat dataMgr is null");
        return ERR_BUNDLE_MANAGER_INTERNAL_ERROR;
    }

    auto userId = AccountHelper::GetUserIdByCallerType();
    if (userId <= Constants::U1) {
        APP_LOGE("Invalid userid: %{public}d", userId);
        return ERR_BUNDLE_MANAGER_INVALID_PARAMETER;
    }
    std::vector<std::tuple<std::string, std::vector<std::string>, std::vector<int32_t>>> validBundles;
    dataMgr->GetBundleCacheInfos(userId, validBundles, true);
    if (!validBundles.empty()) {
        auto getAllBundleCache = [validBundles, userId, processCacheCallback]() {
            uint64_t cacheStat = 0;
            APP_LOGI("thread for GetBundleCacheSize start");
            GetBundleCacheSize(validBundles, userId, cacheStat);
            processCacheCallback->OnGetAllBundleCacheFinished(cacheStat);
        };
        std::thread(getAllBundleCache).detach();
    }
    APP_LOGI("GetAllBundleCacheStat succeed");
    return ERR_OK;
}

ErrCode BundleCacheMgr::CleanBundleCloneCache(const std::string &bundleName, int32_t userId,
    int32_t appCloneIndex, const std::vector<std::string> &moduleNames)
{
    std::vector<std::string> cachePaths = GetBundleCachePath(bundleName, userId, appCloneIndex, moduleNames);
    int32_t result = ERR_OK;
    for (const auto& cache : cachePaths) {
        int32_t ret = InstalldClient::GetInstance()->CleanBundleDataDir(cache);
        if (ret != ERR_OK) {
            result = ret;
            APP_LOGW("CleanBundleDataDir failed, path: %{private}s", cache.c_str());
        }
    }
    return result;
}

ErrCode BundleCacheMgr::CleanBundleCache(const std::vector<std::tuple<std::string,
    std::vector<std::string>, std::vector<int32_t>>> &validBundles, int32_t userId)
{
    int32_t result = ERR_OK;
    for (const auto &item : validBundles) {
        // get cache path for every bundle(contains clone and module)
        std::string bundleName = std::get<INDEX_BUNDLE_NAME>(item);
        std::vector<std::string> moduleNames = std::get<INDEX_MODULE_NAMES>(item);
        std::vector<int32_t> allCloneAppIndex = std::get<INDEX_CLONE_APP_INDEX>(item);
        for (const auto &appIndex : allCloneAppIndex) {
            int32_t ret = CleanBundleCloneCache(bundleName, userId, appIndex, moduleNames);
            if (ret != ERR_OK) {
                result = ret;
                APP_LOGW("CleanBundleCloneCache %{public}s failed, userId: %{public}d, appIndex: %{public}d",
                    bundleName.c_str(), userId, appIndex);
            }
        }
    }
    return result;
}
 
ErrCode BundleCacheMgr::CleanAllBundleCache(const sptr<IProcessCacheCallback> processCacheCallback)
{
    APP_LOGI("start");
    auto dataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
    if (dataMgr == nullptr) {
        return ERR_BUNDLE_MANAGER_INTERNAL_ERROR;
    }
    auto userId = AccountHelper::GetUserIdByCallerType();
    if (userId <= Constants::U1) {
        APP_LOGE("Invalid userid: %{public}d", userId);
        return ERR_BUNDLE_MANAGER_INVALID_PARAMETER;
    }
    std::vector<std::tuple<std::string, std::vector<std::string>, std::vector<int32_t>>> validBundles;
    dataMgr->GetBundleCacheInfos(userId, validBundles, true);
    if (!validBundles.empty()) {
        auto CleanAllBundleCache = [validBundles, userId, processCacheCallback]() {
            ErrCode result = ERR_OK;
            APP_LOGI("thread for CleanBundleCache start");
            result = CleanBundleCache(validBundles, userId);
            processCacheCallback->OnCleanAllBundleCacheFinished(result);
        };
        std::thread(CleanAllBundleCache).detach();
    }
    return ERR_OK;
}
}  // namespace AppExecFwk
}  // namespace OHOS
