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

#include "bundle_backup_mgr.h"

#include "app_log_wrapper.h"
#include <fcntl.h>
#include <fstream>
#include "bundle_backup_service.h"
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/sendfile.h>
#include <unistd.h>

namespace OHOS {
namespace AppExecFwk {

BundleBackupMgr::BundleBackupMgr() {}

BundleBackupMgr::~BundleBackupMgr() {}

ErrCode BundleBackupMgr::OnBackup(MessageParcel& data, MessageParcel& reply)
{
    nlohmann::json backupJson = nlohmann::json::array();
    std::shared_ptr<BundleBackupService> service = DelayedSingleton<BundleBackupService>::GetInstance();
    if (service == nullptr) {
        APP_LOGE("Get BundleBackupService failed");
        return ERR_APPEXECFWK_NULL_PTR;
    }
    auto ret = service->OnBackup(backupJson);
    if (ret != ERR_OK) {
        return ret;
    }
    ret = SaveToFile(backupJson.dump());
    if (ret != ERR_OK) {
        APP_LOGE("Save backup config failed");
        return ret;
    }

    int32_t fd = open(BACKUP_FILE_PATH, O_RDONLY);
    if (fd < 0) {
        APP_LOGE("Open backup file failed");
        return ERR_APPEXECFWK_BACKUP_FILE_IO_ERROR;
    }
    if (!reply.WriteFileDescriptor(fd)) {
        APP_LOGE("Write file descriptor failed");
        close(fd);
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    close(fd);
    return ERR_OK;
}

ErrCode BundleBackupMgr::OnRestore(MessageParcel& data, MessageParcel& reply)
{
    int32_t fd = data.ReadFileDescriptor();
    if (fd < 0) {
        return ERR_APPEXECFWK_BACKUP_INVALID_PARAMETER;
    }
    std::string config;
    auto ret = LoadFromFile(fd, config);
    (void)close(fd);
    if (ret != ERR_OK) {
        APP_LOGE("LoadFromFile failed");
        return ret;
    }
    (void)remove(BACKUP_FILE_PATH);
    if (config.empty() || !nlohmann::json::accept(config)) {
        APP_LOGE("Invalid JSON format");
        return ERR_APPEXECFWK_BACKUP_INVALID_JSON_STRUCTURE;
    }
    auto json = nlohmann::json::parse(config, nullptr, false);
    if (json.is_null()) {
        APP_LOGE("Invalid JSON structure");
        return ERR_APPEXECFWK_BACKUP_INVALID_JSON_STRUCTURE;
    }
    std::shared_ptr<BundleBackupService> service = DelayedSingleton<BundleBackupService>::GetInstance();
    if (service == nullptr) {
        APP_LOGE("Get BundleBackupService failed");
        return ERR_APPEXECFWK_NULL_PTR;
    }
    ret = service->OnRestore(json);
    if (ret != ERR_OK) {
        return ret;
    }
    return ERR_OK;
}

ErrCode BundleBackupMgr::SaveToFile(const std::string& config)
{
    (void)remove(BACKUP_FILE_PATH);
    FILE* fp = fopen(BACKUP_FILE_PATH, "w");
    if (!fp) {
        APP_LOGE("Save config file: %{public}s, fopen() failed", BACKUP_FILE_PATH);
        return ERR_APPEXECFWK_BACKUP_FILE_IO_ERROR;
    }
    int32_t ret = static_cast<int32_t>(fwrite(config.c_str(), 1, config.length(), fp));
    if (ret != (int32_t)config.length()) {
        APP_LOGE("Save config file: %{public}s, fwrite %{public}d failed", BACKUP_FILE_PATH, ret);
        (void)fclose(fp);
        return ERR_APPEXECFWK_BACKUP_FILE_IO_ERROR;
    }
    (void)fflush(fp);
    (void)fsync(fileno(fp));
    (void)fclose(fp);
    APP_LOGI("Save config file %{public}zu", config.size());
    return ERR_OK;
}

ErrCode BundleBackupMgr::LoadFromFile(int32_t fd, std::string& config)
{
    struct stat statBuf;
    if (fstat(fd, &statBuf) < 0) {
        APP_LOGE("Fstat failed, errno: %{public}d", errno);
        return ERR_APPEXECFWK_BACKUP_FILE_IO_ERROR;
    }
    config.resize(statBuf.st_size);
    if (read(fd, config.data(), statBuf.st_size) != statBuf.st_size) {
        APP_LOGE("Read file failed");
        return ERR_APPEXECFWK_BACKUP_FILE_IO_ERROR;
    }
    return ERR_OK;
}
}  // namespace AppExecFwk
}  // namespace OHOS