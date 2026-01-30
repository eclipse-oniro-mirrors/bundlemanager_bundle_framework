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

#ifndef FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_NEW_BUNDLE_DATA_DIR_MGR_H
#define FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_NEW_BUNDLE_DATA_DIR_MGR_H

#include <map>
#include <mutex>
#include <set>
#include <string>

#include "singleton.h"

namespace OHOS {
namespace AppExecFwk {
enum class CreateBundleDirType : uint32_t {
    CREATE_NONE_DIR = 0x00000000,
    CREATE_ALL_DIR = 0x00000001,
    CREATE_EL5_DIR = 0x00000002,
    CREATE_GROUP_DIR = 0x00000004,
};

class NewBundleDataDirMgr : public DelayedSingleton<NewBundleDataDirMgr> {
public:
    NewBundleDataDirMgr();
    ~NewBundleDataDirMgr();
    std::set<std::string> GetAllNewBundleDataDirBundleName();
    bool AddNewBundleDirInfo(const std::string &bundleName, const uint32_t dirType);
    bool AddAllUserId(const std::set<int32_t> userIds);
    bool DeleteUserId(const int32_t userId);
    bool ProcessOtaBundleDataDir(const std::string &bundleName, const int32_t userId);
    std::set<std::string> GetAllBundleDataDirEl5BundleName(const int32_t userId);
    bool ProcessOtaBundleDataDirEl5(const int32_t userId);

private:
    uint32_t GetNewBundleDataDirType(const std::string &bundleName, const int32_t userId);
    std::mutex &GetBundleMutex(const std::string &bundleName);
    bool InnerProcessOtaNewInstallBundleDir(const std::string &bundleName, const int32_t userId);
    bool InnerProcessOtaBundleDataDirEl5(const std::string &bundleName, const int32_t userId);
    bool InnerProcessOtaBundleDataDirGroup(const std::string &bundleName, const int32_t userId);
    bool LoadNewBundleDataDirInfosFromDb();
    bool AddNewBundleDataDirInfosToDb();
    bool DeleteNewBundleDataDirInfosFromDb();

    bool hasInit_ = false;
    std::mutex newBundleDataDirMutex_;
    std::map<std::string, uint32_t> newBundleDataDirMap_;
    std::set<int32_t> userIds_;
    std::mutex bundleMutex_;
    std::unordered_map<std::string, std::mutex> bundleMutexMap_;
};
}  // namespace AppExecFwk
}  // namespace OHOS
#endif  // FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_NEW_BUNDLE_DATA_DIR_MGR_H
