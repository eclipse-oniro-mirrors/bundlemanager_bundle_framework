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

#include "bundle_permissions.h"

#include "app_log_wrapper.h"

namespace OHOS {
namespace AppExecFwk {
PermissionStringPool &PermissionStringPool::GetInstance()
{
    static PermissionStringPool instance;
    return instance;
}

uint32_t PermissionStringPool::GetOrAddIndex(const std::string &str)
{
    if (str.empty()) {
        return INVALID_STRING_IDX;
    }

    {
        std::shared_lock<std::shared_mutex> readLock(mutex_);
        auto it = stringToIdx_.find(str);
        if (it != stringToIdx_.end()) {
            return it->second;
        }
    }

    std::unique_lock<std::shared_mutex> writeLock(mutex_);
    auto it = stringToIdx_.find(str);
    if (it != stringToIdx_.end()) {
        return it->second;
    }
    if (strings_.size() >= INVALID_STRING_IDX) {
        APP_LOGE_NOFUNC("permission string pool is full, cannot add: %{public}s", str.c_str());
        return INVALID_STRING_IDX;
    }
    uint32_t newIdx = static_cast<uint32_t>(strings_.size());
    strings_.push_back(str);
    // key views the pool-owned string, not the caller's argument
    stringToIdx_.emplace(std::string_view(strings_.back()), newIdx);
    return newIdx;
}

void PermissionStringPool::AppendStrings(
    const std::vector<uint32_t> &indices, std::vector<std::string> &out) const
{
    out.reserve(out.size() + indices.size());
    std::shared_lock<std::shared_mutex> readLock(mutex_);
    for (uint32_t idx : indices) {
        if (idx < strings_.size()) {
            out.push_back(strings_[idx]);
        } else {
            out.emplace_back();
        }
    }
}

void PermissionStringPool::Defrag()
{
    APP_LOGI_NOFUNC("start to defrag PermissionStringPool memory");
    std::unique_lock<std::shared_mutex> writeLock(mutex_);
    std::deque<std::string> newStrings;
    std::unordered_map<std::string_view, uint32_t> newStringToIdx;
    newStringToIdx.reserve(stringToIdx_.size());
    for (size_t i = 0; i < strings_.size(); ++i) {
        newStrings.push_back(strings_[i]);
        // key views the rebuilt pool string; deque::swap below keeps element addresses stable
        newStringToIdx.emplace(std::string_view(newStrings.back()), static_cast<uint32_t>(i));
    }
    strings_.swap(newStrings);
    stringToIdx_.swap(newStringToIdx);
    APP_LOGI_NOFUNC("defrag PermissionStringPool memory done");
}

bool BundlePermissions::IsComplexPermission(const RequestPermission &permission)
{
    return permission.reasonId != 0 ||
        !permission.reason.empty() ||
        !permission.requiredFeature.empty() ||
        !permission.usedScene.when.empty() ||
        !permission.usedScene.abilities.empty();
}

void BundlePermissions::AddPermission(const RequestPermission &permission)
{
    if (permission.name.empty()) {
        return;
    }

    uint32_t nameIdx = PermissionStringPool::GetInstance().GetOrAddIndex(permission.name);
    if (nameIdx == INVALID_STRING_IDX) {
        APP_LOGE_NOFUNC("add permission name to pool failed: %{public}s", permission.name.c_str());
        return;
    }

    if (IsComplexPermission(permission)) {
        ComplexPermission complexPerm;
        complexPerm.nameIdx = nameIdx;
        complexPerm.reasonId = permission.reasonId;
        complexPerm.reason = permission.reason;
        complexPerm.requiredFeature = permission.requiredFeature;
        complexPerm.usedScene = permission.usedScene;
        complexPermissions.push_back(std::move(complexPerm));
    } else {
        simplePermissions.push_back(nameIdx);
    }
}

void BundlePermissions::AppendPermissionNames(std::vector<std::string> &out) const
{
    std::vector<uint32_t> indices;
    indices.reserve(simplePermissions.size() + complexPermissions.size());
    indices.insert(indices.end(), simplePermissions.begin(), simplePermissions.end());
    for (const auto &complexPerm : complexPermissions) {
        indices.push_back(complexPerm.nameIdx);
    }
    PermissionStringPool::GetInstance().AppendStrings(indices, out);
}

BundlePermissions ToBundlePermissions(const std::vector<RequestPermission> &reqPermissions)
{
    BundlePermissions bundlePermissions;
    for (const auto &permission : reqPermissions) {
        bundlePermissions.AddPermission(permission);
    }
    return bundlePermissions;
}

std::vector<RequestPermission> ToRequestPermissions(
    const BundlePermissions &bundlePermissions, const std::string &moduleName)
{
    const auto &simplePermissions = bundlePermissions.simplePermissions;
    const auto &complexPermissions = bundlePermissions.complexPermissions;

    // resolve all names (simple first, then complex) in a single read lock
    std::vector<uint32_t> indices;
    indices.reserve(simplePermissions.size() + complexPermissions.size());
    indices.insert(indices.end(), simplePermissions.begin(), simplePermissions.end());
    for (const auto &complexPerm : complexPermissions) {
        indices.push_back(complexPerm.nameIdx);
    }
    std::vector<std::string> names;
    PermissionStringPool::GetInstance().AppendStrings(indices, names);

    std::vector<RequestPermission> result;
    result.reserve(simplePermissions.size() + complexPermissions.size());
    size_t nameIndex = 0;
    for (; nameIndex < simplePermissions.size(); ++nameIndex) {
        RequestPermission perm;
        perm.name = std::move(names[nameIndex]);
        perm.moduleName = moduleName;
        result.push_back(std::move(perm));
    }
    for (const auto &complexPerm : complexPermissions) {
        RequestPermission perm;
        perm.name = std::move(names[nameIndex++]);
        perm.moduleName = moduleName;
        perm.reasonId = complexPerm.reasonId;
        perm.reason = complexPerm.reason;
        perm.requiredFeature = complexPerm.requiredFeature;
        perm.usedScene = complexPerm.usedScene;
        result.push_back(std::move(perm));
    }
    return result;
}
}  // namespace AppExecFwk
}  // namespace OHOS
