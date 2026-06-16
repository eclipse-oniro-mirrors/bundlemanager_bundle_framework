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

#ifndef FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_BUNDLE_PERMISSIONS_H
#define FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_BUNDLE_PERMISSIONS_H

#include <cstdint>
#include <deque>
#include <shared_mutex>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

#include "bundle_info.h"

namespace OHOS {
namespace AppExecFwk {
constexpr uint32_t INVALID_STRING_IDX = UINT32_MAX;

class PermissionStringPool {
public:
    static PermissionStringPool &GetInstance();
    /**
     * @brief Get the index of str, inserting it when absent.
     * @param str indicates the permission name.
     * @return Returns the index; returns INVALID_STRING_IDX when str is empty or the pool is full.
     */
    uint32_t GetOrAddIndex(const std::string &str);
    /**
     * @brief Append the strings for indices to out, taking the read lock once.
     */
    void AppendStrings(const std::vector<uint32_t> &indices, std::vector<std::string> &out) const;
    /**
     * @brief Reallocate the backing storage while keeping every index unchanged.
     */
    void Defrag();

private:
    PermissionStringPool() = default;
    ~PermissionStringPool() = default;
    PermissionStringPool(const PermissionStringPool &) = delete;
    PermissionStringPool &operator=(const PermissionStringPool &) = delete;

    mutable std::shared_mutex mutex_;
    std::deque<std::string> strings_;
    // keys are views into strings_, avoiding a second copy of every name
    std::unordered_map<std::string_view, uint32_t> stringToIdx_;
};

struct ComplexPermission {
    uint32_t nameIdx = INVALID_STRING_IDX;
    uint32_t reasonId = 0;
    std::string reason;
    std::string requiredFeature;
    RequestPermissionUsedScene usedScene;
};

struct BundlePermissions {
    std::vector<uint32_t> simplePermissions;
    std::vector<ComplexPermission> complexPermissions;

    void AddPermission(const RequestPermission &permission);
    void AppendPermissionNames(std::vector<std::string> &out) const;
    static bool IsComplexPermission(const RequestPermission &permission);
};

BundlePermissions ToBundlePermissions(const std::vector<RequestPermission> &reqPermissions);
std::vector<RequestPermission> ToRequestPermissions(
    const BundlePermissions &bundlePermissions, const std::string &moduleName = "");
}  // namespace AppExecFwk
}  // namespace OHOS

#endif  // FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_BUNDLE_PERMISSIONS_H
