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

#include "bundle_cache_mgr.h"
#include "bundle_mgr_service.h"

namespace OHOS {
namespace AppExecFwk {

namespace {
constexpr size_t INDEX_BUNDLE_NAME = 0;
constexpr size_t INDEX_MODULE_NAMES = 1;
constexpr size_t INDEX_CLONE_APP_INDEX = 2;
}

std::vector<std::string> BundleCacheMgr::GetBundleCachePath(const std::string &bundleName,
    const int32_t userId, const int32_t appIndex, const std::vector<std::string> &moduleNameList)
{
    std::string bundleNameDir = bundleName;
    if (appIndex > 0) {
        bundleNameDir = BundleCloneCommonHelper::GetCloneDataDir(bundleName, appIndex);
    }
    std::vector<std::string> cachePaths;
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
    for (const auto &item : validBundles) {
        // get cache path for every bundle(contains clone and module)
        std::string bundleName = std::get<INDEX_BUNDLE_NAME>(item);
        std::vector<std::string> moduleNames = std::get<INDEX_MODULE_NAMES>(item);
        std::vector<int32_t> allCloneAppIndex = std::get<INDEX_CLONE_APP_INDEX>(item);
        for (const auto &appIndex : allCloneAppIndex) {
            std::vector<std::string> cachePaths = GetBundleCachePath(bundleName, userId, appIndex, moduleNames);
            int64_t cacheSize = InstalldClient::GetInstance()->GetDiskUsageFromPath(cachePaths);
            cacheStat += static_cast<uint64_t>(cacheSize);
        }
    }
    return;
}

ErrCode BundleCacheMgr::GetAllBundleCacheStat(const sptr<IProcessCacheCallback> processCacheCallback)
{
    APP_LOGI("start");
    auto dataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
    if (dataMgr == nullptr) {
        return ERR_BUNDLE_MANAGER_INTERNAL_ERROR;
    }

    auto userId = AccountHelper::GetCurrentActiveUserId();
    if (userId <= Constants::DEFAULT_USERID) {
        APP_LOGE("Invalid userid: %{public}d", userId);
        return ERR_BUNDLE_MANAGER_INVALID_PARAMETER;
    }
    std::vector<std::tuple<std::string, std::vector<std::string>, std::vector<int32_t>>> validBundles;
    std::map<std::string, InnerBundleInfo> bundleInfos = dataMgr->GetAllInnerBundleInfos();
    for (const auto &item : bundleInfos) {
        const InnerBundleInfo &info = item.second;
        std::string bundleName = info.GetBundleName();
        std::vector<std::string> moduleNameList;
        info.GetModuleNames(moduleNameList);
        std::vector<int32_t> allAppIndexes = {0};
        std::vector<int32_t> cloneAppIndexes = dataMgr->GetCloneAppIndexesByInnerBundleInfo(info, userId);
        allAppIndexes.insert(allAppIndexes.end(), cloneAppIndexes.begin(), cloneAppIndexes.end());
        validBundles.emplace_back(std::make_tuple(bundleName, moduleNameList, allAppIndexes));
        // add atomic service
        if (info.GetApplicationBundleType() == BundleType::ATOMIC_SERVICE) {
            std::string atomicServiceName;
            AccountSA::OhosAccountInfo accountInfo;
            auto ret = dataMgr->GetDirForAtomicServiceByUserId(bundleName, userId, accountInfo, atomicServiceName);
            if (ret != ERR_OK) {
                APP_LOGW("GetDirForAtomicServiceByUserId failed bundleName: %{public}s", bundleName.c_str());
                continue;
            }
            if (!atomicServiceName.empty()) {
                validBundles.emplace_back(std::make_tuple(atomicServiceName, moduleNameList, allAppIndexes));
                APP_LOGD("atomicServiceName: %{public}s", atomicServiceName.c_str());
            }
        }
    }

    auto getAllBundleCache = [validBundles, userId, processCacheCallback]() {
        uint64_t cacheStat = 0;
        APP_LOGI("thread for GetBundleCacheSize start");
        GetBundleCacheSize(validBundles, userId, cacheStat);
        processCacheCallback->OnGetAllBundleCacheFinished(cacheStat);
    };
    std::thread(getAllBundleCache).detach();
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
    int32_t ret = ERR_OK;
    for (const auto &item : validBundles) {
        // get cache path for every bundle(contains clone and module)
        std::string bundleName = std::get<INDEX_BUNDLE_NAME>(item);
        std::vector<std::string> moduleNames = std::get<INDEX_MODULE_NAMES>(item);
        std::vector<int32_t> allCloneAppIndex = std::get<INDEX_CLONE_APP_INDEX>(item);
        for (const auto &appIndex : allCloneAppIndex) {
            ret = CleanBundleCloneCache(bundleName, userId, appIndex, moduleNames);
            if (ERR_OK != ret) {
                APP_LOGW("CleanNoRunningCloneCache %{public}s failed, userId: %{public}d, appIndex: %{public}d",
                    bundleName.c_str(), userId, appIndex);
            }
        }
    }
    return ret;
}
 
ErrCode BundleCacheMgr::CleanAllBundleCache(const sptr<IProcessCacheCallback> processCacheCallback)
{
    APP_LOGI("start");
    auto dataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
    if (dataMgr == nullptr) {
        return ERR_BUNDLE_MANAGER_INTERNAL_ERROR;
    }
    auto userId = AccountHelper::GetCurrentActiveUserId();
    if (userId <= Constants::DEFAULT_USERID) {
        APP_LOGE("Invalid userid: %{public}d", userId);
        return ERR_BUNDLE_MANAGER_INVALID_PARAMETER;
    }
    std::vector<std::tuple<std::string, std::vector<std::string>, std::vector<int32_t>>> validBundles;
    dataMgr->GetCleanBundleCacheInfos(userId, validBundles);
    if (!validBundles.empty()) {
        auto CleanAllBundleCache = [validBundles, userId, processCacheCallback]() {
            bool succeed = true;
            APP_LOGI("thread for CleanBundleCache start");
            succeed = CleanBundleCache(validBundles, userId);
            processCacheCallback->OnCleanAllBundleCacheFinished(succeed);
        };
        std::thread(CleanAllBundleCache).detach();
    }
    return ERR_OK;
}
}  // namespace AppExecFwk
}  // namespace OHOS
