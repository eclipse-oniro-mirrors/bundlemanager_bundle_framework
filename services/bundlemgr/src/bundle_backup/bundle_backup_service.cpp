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

#include "bundle_backup_service.h"

#include <mutex>
#include <shared_mutex>

#include "account_helper.h"
#include "app_log_wrapper.h"
#include "bundle_constants.h"
#include "bundle_mgr_service.h"
#include "enterprise_cert_backup_helper.h"
#include "parameters.h"
#include "shortcut_data_storage_rdb.h"

namespace OHOS {
namespace AppExecFwk {

BundleBackupService::BundleBackupService()
{
    shortcutStorage_ = std::make_shared<ShortcutDataStorageRdb>();
    dataMgr_ = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
}

BundleBackupService::~BundleBackupService() {}

ErrCode BundleBackupService::OnBackup(nlohmann::json &jsonObject)
{
    // Segment-independent backup: a shortcut failure does not block the cert segment;
    // a single failure returns its own code, both failed returns the combined code.
    // On non-ERR_OK the caller writes no file and returns no fd, so no partial backup.
    ErrCode shortcutRet = ERR_OK;
    jsonObject = nlohmann::json::object();
    jsonObject[ServiceConstants::BACKUP_VERSION_KEY] = ServiceConstants::BACKUP_FORMAT_VERSION;
    nlohmann::json shortcuts = nlohmann::json::array();
    if (!shortcutStorage_->GetAllTableDataToJson(shortcuts)) {
        APP_LOGE("Failed to get shortcuts from storage");
        shortcutRet = ERR_APPEXECFWK_DB_GET_DATA_ERROR;
    }
    jsonObject[ServiceConstants::BACKUP_SHORTCUTS_KEY] = shortcuts;
    // Mutual exclusion with EDM Add/Delete APIs (enterpriseCertMutex_) for an atomic snapshot.
    auto installer = DelayedSingleton<BundleMgrService>::GetInstance()->GetBundleInstaller();
    std::unique_lock<std::shared_mutex> certLock;
    if (installer != nullptr) {
        certLock = installer->AcquireEnterpriseCertLock();
    } else {
        APP_LOGW("get bundle installer failed, backup without cross-entry cert lock");
    }
    nlohmann::json certs = nlohmann::json::array();
    ErrCode certRet = ERR_OK;
    // Backup follows the per-user session model: each user backs up to their own
    // media, so only the foreground user's certs may enter this backup file.
    int32_t activeUserId = AccountHelper::GetCurrentActiveUserId();
    if (activeUserId == Constants::INVALID_USERID) {
        // Fail the backup instead of silently producing one without certs.
        APP_LOGE("get current active userId failed, skip enterprise cert backup");
        certRet = ERR_APPEXECFWK_BACKUP_INVALID_PARAMETER;
    } else {
        certRet = EnterpriseCertBackupHelper::BackupToJson(certs, {activeUserId});
    }
    if (certLock.owns_lock()) {
        certLock.unlock();
    }
    if (certRet != ERR_OK) {
        APP_LOGE("Backup enterprise resign certs failed, err is %{public}d", certRet);
    }
    jsonObject[ServiceConstants::BACKUP_ENTERPRISE_CERTS_KEY] = certs;
    // Total-size pre-check against the CAPACITY_SIZE limit enforced by LoadFromFile on
    // restore; fail fast to avoid a backup that can never be restored.
    ErrCode sizeRet = ERR_OK;
    std::string config = jsonObject.dump();
    if (config.size() > static_cast<size_t>(Constants::CAPACITY_SIZE)) {
        APP_LOGE("backup config too large: %{public}zu", config.size());
        sizeRet = ERR_APPEXECFWK_BACKUP_FILE_IO_ERROR;
    }
    if (shortcutRet != ERR_OK && certRet != ERR_OK) {
        APP_LOGE("backup failed in both segments, shortcut: %{public}d, cert: %{public}d",
            shortcutRet, certRet);
        return ERR_APPEXECFWK_BACKUP_BOTH_FAILED;
    }
    if (shortcutRet != ERR_OK) {
        return shortcutRet;
    }
    if (certRet != ERR_OK) {
        return certRet;
    }
    return sizeRet;
}

ErrCode BundleBackupService::OnRestore(nlohmann::json &jsonObject)
{
    if (dataMgr_ == nullptr) {
        return ERR_APPEXECFWK_NULL_PTR;
    }
    if (jsonObject.is_array()) {
        // legacy v1 format: shortcuts only
        dataMgr_->FilterShortcutJson(jsonObject);
        if (!shortcutStorage_->UpdateAllShortcuts(jsonObject)) {
            APP_LOGE("Failed to clear shortcut table");
            return ERR_APPEXECFWK_DB_UPDATE_ERROR;
        }
        return ERR_OK;
    }
    if (!jsonObject.is_object() || !jsonObject.contains(ServiceConstants::BACKUP_VERSION_KEY) ||
        !jsonObject.at(ServiceConstants::BACKUP_VERSION_KEY).is_number_integer()) {
        APP_LOGE("Invalid backup json structure or unsupported version");
        return ERR_APPEXECFWK_BACKUP_INVALID_JSON_STRUCTURE;
    }
    int32_t version = jsonObject.at(ServiceConstants::BACKUP_VERSION_KEY).get<int32_t>();
    if (version < 1 || version > ServiceConstants::BACKUP_FORMAT_VERSION) {
        APP_LOGE("Unsupported backup version: %{public}d", version);
        return ERR_APPEXECFWK_BACKUP_INVALID_JSON_STRUCTURE;
    }
    // Segment-independent restore: a shortcut failure does not block the cert segment
    // (certs are a hard dependency of enterprise app install); a single failure returns
    // its own code, both failed returns the combined code.
    ErrCode shortcutRet = ERR_OK;
    if (jsonObject.contains(ServiceConstants::BACKUP_SHORTCUTS_KEY) &&
        jsonObject.at(ServiceConstants::BACKUP_SHORTCUTS_KEY).is_array()) {
        nlohmann::json shortcuts = jsonObject.at(ServiceConstants::BACKUP_SHORTCUTS_KEY);
        dataMgr_->FilterShortcutJson(shortcuts);
        if (!shortcutStorage_->UpdateAllShortcuts(shortcuts)) {
            APP_LOGE("Failed to clear shortcut table");
            shortcutRet = ERR_APPEXECFWK_DB_UPDATE_ERROR;
        }
    }
    ErrCode certRet = ERR_OK;
    if (jsonObject.contains(ServiceConstants::BACKUP_ENTERPRISE_CERTS_KEY)) {
        certRet = RestoreEnterpriseCerts(jsonObject.at(ServiceConstants::BACKUP_ENTERPRISE_CERTS_KEY));
    }
    if (shortcutRet != ERR_OK && certRet != ERR_OK) {
        APP_LOGE("restore failed in both segments, shortcut: %{public}d, cert: %{public}d",
            shortcutRet, certRet);
        return ERR_APPEXECFWK_RESTORE_BOTH_FAILED;
    }
    if (shortcutRet != ERR_OK) {
        return shortcutRet;
    }
    return certRet;
}

ErrCode BundleBackupService::RestoreEnterpriseCerts(const nlohmann::json &certs)
{
    if (!certs.is_array()) {
        APP_LOGE("Invalid enterprise resign certs json structure");
        return ERR_APPEXECFWK_BACKUP_INVALID_JSON_STRUCTURE;
    }
    if (!OHOS::system::GetBoolParameter(ServiceConstants::IS_ENTERPRISE_DEVICE, false)) {
        // Review decision 2026-08-19: skip cert restore on non-enterprise devices
        // instead of failing the whole system data restore.
        APP_LOGI("not enterprise device, skip enterprise resign certs restore");
        return ERR_OK;
    }
    // Mutual exclusion with EDM Add/Delete APIs (enterpriseCertMutex_) keeps
    // the cert set stable during restore.
    auto installer = DelayedSingleton<BundleMgrService>::GetInstance()->GetBundleInstaller();
    std::unique_lock<std::shared_mutex> certLock;
    if (installer != nullptr) {
        certLock = installer->AcquireEnterpriseCertLock();
    } else {
        APP_LOGW("get bundle installer failed, restore without cross-entry cert lock");
    }
    ErrCode certRet = ERR_OK;
    int32_t activeUserId = AccountHelper::GetCurrentActiveUserId();
    if (activeUserId == Constants::INVALID_USERID) {
        // Restoring certs without a user scope could touch the wrong user's dir;
        // fail the cert segment instead of reporting silent success.
        APP_LOGE("get current active userId failed, skip enterprise cert restore");
        certRet = ERR_APPEXECFWK_BACKUP_INVALID_PARAMETER;
    } else {
        certRet = EnterpriseCertBackupHelper::RestoreFromJson(
            FilterCertsByCurrentUser(certs, activeUserId));
    }
    if (certLock.owns_lock()) {
        certLock.unlock();
    }
    if (certRet != ERR_OK) {
        APP_LOGE("Restore enterprise resign certs failed, err is %{public}d", certRet);
    }
    return certRet;
}

nlohmann::json BundleBackupService::FilterCertsByCurrentUser(
    const nlohmann::json &certsArray, int32_t currentUserId) const
{
    nlohmann::json filtered = nlohmann::json::array();
    for (const auto &item : certsArray) {
        if (!item.is_object() || !item.contains(ServiceConstants::BACKUP_CERT_USER_ID_KEY) ||
            !item.at(ServiceConstants::BACKUP_CERT_USER_ID_KEY).is_number_integer()) {
            APP_LOGW("skip cert item without valid userId");
            continue;
        }
        int32_t userId = item.at(ServiceConstants::BACKUP_CERT_USER_ID_KEY).get<int32_t>();
        if (userId != currentUserId) {
            // Other users' certs are restored in their own sessions; a file from the
            // legacy all-user format is degraded gracefully by dropping them.
            APP_LOGW("userId %{public}d is not current user %{public}d, skip its certs", userId, currentUserId);
            continue;
        }
        filtered.push_back(item);
    }
    return filtered;
}
}  // namespace AppExecFwk
}  // namespace OHOS
