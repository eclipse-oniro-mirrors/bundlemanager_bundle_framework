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

#include "enterprise_cert_backup_helper.h"

#include <dirent.h>
#include <sys/stat.h>

#include <cerrno>
#include <cstdint>
#include <fstream>
#include <map>
#include <mutex>
#include <string>
#include <vector>

#include "app_log_wrapper.h"
#include "bundle_constants.h"
#include "installd_client.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
constexpr uint8_t BIT_EIGHT = 8;       // bits of one byte
constexpr uint8_t BIT_SIX = 6;         // bits of one base64 digit
constexpr int32_t LEN_THREE = 3;       // byte count of one full base64 group
constexpr int32_t LEN_FOUR = 4;        // digit count of one full base64 group
constexpr uint32_t BASE64_MASK = 0x3F; // low 6 bits of one base64 digit
constexpr uint32_t BYTE_MASK = 0xFF;   // low 8 bits of one byte
const char BASE64_CHARS[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

// Serialize backup and restore (design doc section 4.8).
std::mutex g_certBackupMutex;

// Base64 encode: each 3 bytes (24 bits) become 4 6-bit table lookups;
// a trailing partial group is padded with '=' to a multiple of 4 (RFC 4648).
bool EncodeBase64(const std::string &in, std::string &out)
{
    if (in.empty()) {
        return false;
    }
    out.clear();
    out.reserve(((in.size() + LEN_THREE - 1) / LEN_THREE) * LEN_FOUR);
    uint32_t val = 0;
    int32_t bits = -BIT_SIX;
    for (unsigned char c : in) {
        val = (val << BIT_EIGHT) + c;
        bits += BIT_EIGHT;
        while (bits >= 0) {
            out.push_back(BASE64_CHARS[(val >> bits) & BASE64_MASK]);
            bits -= BIT_SIX;
        }
    }
    if (bits > -BIT_SIX) {
        out.push_back(BASE64_CHARS[((val << BIT_EIGHT) >> (bits + BIT_EIGHT)) & BASE64_MASK]);
    }
    while (out.size() % LEN_FOUR != 0) {
        out.push_back('=');
    }
    return true;
}

// Base64 alphabet values: A-Z=0..25, a-z=26..51, 0-9=52..61, '+'=62, '/'=63.
int32_t Base64CharValue(char c)
{
    if (c >= 'A' && c <= 'Z') {
        return c - 'A';
    }
    if (c >= 'a' && c <= 'z') {
        return c - 'a' + 26;
    }
    if (c >= '0' && c <= '9') {
        return c - '0' + 52;
    }
    if (c == '+') {
        return 62;
    }
    if (c == '/') {
        return 63;
    }
    return -1;
}

bool DecodeBase64(const std::string &in, std::string &out)
{
    if (in.empty() || in.size() % LEN_FOUR == 1) {
        return false;
    }
    out.clear();
    out.reserve(in.size() / LEN_FOUR * LEN_THREE);
    uint32_t val = 0;
    int32_t bits = -BIT_EIGHT;
    for (char c : in) {
        if (c == '=') {
            break;
        }
        int32_t v = Base64CharValue(c);
        if (v < 0) {
            return false;
        }
        val = (val << BIT_SIX) + static_cast<uint32_t>(v);
        bits += BIT_SIX;
        if (bits >= 0) {
            out.push_back(static_cast<char>((val >> bits) & BYTE_MASK));
            bits -= BIT_EIGHT;
        }
    }
    // '=' is only allowed at the end (at most 2) with no other characters after it.
    size_t pos = in.find('=');
    if (pos != std::string::npos) {
        if (in.size() - pos > 2 || in.find_first_not_of('=', pos) != std::string::npos) {
            return false;
        }
    }
    return !out.empty();
}

bool EndWith(const std::string &str, const std::string &suffix)
{
    return str.size() >= suffix.size() &&
        str.compare(str.size() - suffix.size(), suffix.size(), suffix) == 0;
}

bool IsDir(const std::string &path)
{
    struct stat st {};
    return stat(path.c_str(), &st) == 0 && S_ISDIR(st.st_mode);
}

bool ReadFileContent(const std::string &path, std::string &content)
{
    std::ifstream ifs(path, std::ios::binary | std::ios::ate);
    if (!ifs.is_open()) {
        APP_LOGE("open cert file failed, path: %{private}s", path.c_str());
        return false;
    }
    std::streampos size = ifs.tellg();
    if (size < 0 || static_cast<uint64_t>(size) > static_cast<uint64_t>(Constants::CAPACITY_SIZE)) {
        APP_LOGE("cert file size invalid, path: %{private}s", path.c_str());
        return false;
    }
    content.resize(static_cast<size_t>(size));
    ifs.seekg(0, std::ios::beg);
    if (size > 0) {
        ifs.read(content.data(), size);
    }
    return ifs.good() || ifs.eof();
}

struct CertItem {
    int32_t userId = 0;
    std::string alias;
    std::string content;
};

ErrCode ParseAndValidateCerts(const nlohmann::json &certsArray, std::vector<CertItem> &items)
{
    if (!certsArray.is_array()) {
        APP_LOGE("certs json is not array");
        return ERR_APPEXECFWK_BACKUP_ENTERPRISE_CERT_PARAM_ERROR;
    }
    std::map<int32_t, int32_t> userCertCount;
    for (const auto &item : certsArray) {
        if (!item.is_object() || !item.contains(ServiceConstants::BACKUP_CERT_USER_ID_KEY) ||
            !item.contains(ServiceConstants::BACKUP_CERT_ALIAS_KEY) ||
            !item.contains(ServiceConstants::BACKUP_CERT_CONTENT_KEY)) {
            APP_LOGE("cert item missing fields");
            return ERR_APPEXECFWK_BACKUP_ENTERPRISE_CERT_PARAM_ERROR;
        }
        if (!item.at(ServiceConstants::BACKUP_CERT_USER_ID_KEY).is_number_integer()) {
            APP_LOGE("cert userId is not integer");
            return ERR_APPEXECFWK_BACKUP_ENTERPRISE_CERT_PARAM_ERROR;
        }
        int32_t userId = item.at(ServiceConstants::BACKUP_CERT_USER_ID_KEY).get<int32_t>();
        if (userId < Constants::START_USERID) {
            APP_LOGE("cert userId invalid: %{public}d", userId);
            return ERR_APPEXECFWK_BACKUP_ENTERPRISE_CERT_PARAM_ERROR;
        }
        if (!item.at(ServiceConstants::BACKUP_CERT_ALIAS_KEY).is_string() ||
            !item.at(ServiceConstants::BACKUP_CERT_CONTENT_KEY).is_string()) {
            APP_LOGE("cert alias or content is not string");
            return ERR_APPEXECFWK_BACKUP_ENTERPRISE_CERT_PARAM_ERROR;
        }
        std::string alias = item.at(ServiceConstants::BACKUP_CERT_ALIAS_KEY).get<std::string>();
        if (alias.empty() || alias.size() > static_cast<size_t>(Constants::MAX_FILE_NAME_LENGTH) ||
            !EndWith(alias, ServiceConstants::CER_SUFFIX) ||
            alias.find(ServiceConstants::PATH_SEPARATOR) != std::string::npos) {
            APP_LOGE("cert alias invalid: %{public}s", alias.c_str());
            return ERR_APPEXECFWK_BACKUP_ENTERPRISE_CERT_PARAM_ERROR;
        }
        std::string encoded = item.at(ServiceConstants::BACKUP_CERT_CONTENT_KEY).get<std::string>();
        std::string content;
        if (!DecodeBase64(encoded, content) || content.empty() ||
            content.size() > static_cast<size_t>(Constants::CAPACITY_SIZE)) {
            APP_LOGE("cert content invalid, encoded size: %{public}zu", encoded.size());
            return ERR_APPEXECFWK_BACKUP_ENTERPRISE_CERT_PARAM_ERROR;
        }
        if (++userCertCount[userId] > ServiceConstants::MAX_ENTERPRISE_RESIGN_CERT_NUM) {
            APP_LOGE("cert num exceed max for user: %{public}d", userId);
            return ERR_APPEXECFWK_BACKUP_ENTERPRISE_CERT_PARAM_ERROR;
        }
        items.push_back(CertItem{userId, alias, content});
    }
    return ERR_OK;
}

std::string BuildCertFilePath(const std::string &certRootDir, int32_t userId, const std::string &alias)
{
    return certRootDir + ServiceConstants::PATH_SEPARATOR + std::to_string(userId)
        + ServiceConstants::PATH_SEPARATOR + alias;
}

// Memory budget of the local cert snapshot; beyond it rollback only deletes reinstalled items.
constexpr size_t SNAPSHOT_MAX_TOTAL_SIZE = 4 * 1024 * 1024;

struct SnapshotCert {
    int32_t userId = 0;
    std::string alias;
    std::string content;
};

struct LocalCertSnapshot {
    std::vector<SnapshotCert> certs;
    size_t totalSize = 0;
    bool complete = true;
};

// Best-effort capture before clearing; read failure or over budget sets complete=false.
void CaptureLocalCert(const std::string &certRootDir, int32_t userId, const std::string &alias,
    LocalCertSnapshot &snapshot)
{
    if (!snapshot.complete) {
        return;
    }
    std::string content;
    if (!ReadFileContent(BuildCertFilePath(certRootDir, userId, alias), content) ||
        snapshot.totalSize + content.size() > SNAPSHOT_MAX_TOTAL_SIZE) {
        snapshot.complete = false;
        APP_LOGW("local cert snapshot incomplete, full rollback unavailable");
        return;
    }
    snapshot.certs.push_back(SnapshotCert{userId, alias, content});
    snapshot.totalSize += content.size();
}

// Full rollback: delete certs restored in this round and reinstall the pre-clear
// snapshot, so a failed restore leaves the device as before (not zero certs).
ErrCode RollbackRestoredCerts(const std::vector<std::string> &restoredPaths,
    const LocalCertSnapshot &snapshot, const std::string &certRootDir)
{
    for (const auto &path : restoredPaths) {
        ErrCode delRet = InstalldClient::GetInstance()->DeleteCertAndRemoveKey({path});
        if (delRet != ERR_OK) {
            APP_LOGE("rollback delete cert failed, err: %{public}d", delRet);
        }
    }
    if (snapshot.certs.empty()) {
        APP_LOGW("no local cert snapshot to rollback, device left with cleared certs");
        return ERR_APPEXECFWK_BACKUP_ENTERPRISE_CERT_RESTORE_FAILED;
    }
    for (const auto &cert : snapshot.certs) {
        ErrCode addRet = InstalldClient::GetInstance()->AddCertAndEnableKey(
            BuildCertFilePath(certRootDir, cert.userId, cert.alias), cert.content);
        if (addRet != ERR_OK) {
            APP_LOGE("rollback reinstall local cert failed, err: %{public}d", addRet);
        }
    }
    return ERR_APPEXECFWK_BACKUP_ENTERPRISE_CERT_RESTORE_FAILED;
}

// Back up all certs in one user dir (.cer -> base64 -> JSON array).
ErrCode BackupUserCerts(int32_t userId, const std::string &userDir, nlohmann::json &certsArray)
{
    DIR *userDirHandle = opendir(userDir.c_str());
    if (userDirHandle == nullptr) {
        APP_LOGE("opendir user dir failed, errno: %{public}d", errno);
        return ERR_APPEXECFWK_BACKUP_FILE_IO_ERROR;
    }
    ErrCode ret = ERR_OK;
    struct dirent *fileEntry = nullptr;
    while (ret == ERR_OK && (fileEntry = readdir(userDirHandle)) != nullptr) {
        if (fileEntry->d_type != DT_REG) {
            continue;
        }
        std::string fileName(fileEntry->d_name);
        if (!EndWith(fileName, ServiceConstants::CER_SUFFIX) ||
            fileName.size() > static_cast<size_t>(Constants::MAX_FILE_NAME_LENGTH)) {
            APP_LOGW("skip invalid cert file: %{public}s", fileName.c_str());
            continue;
        }
        std::string content;
        if (!ReadFileContent(userDir + ServiceConstants::PATH_SEPARATOR + fileName, content)) {
            ret = ERR_APPEXECFWK_BACKUP_FILE_IO_ERROR;
            break;
        }
        std::string encoded;
        if (!EncodeBase64(content, encoded)) {
            APP_LOGE("base64 encode failed");
            ret = ERR_APPEXECFWK_BACKUP_FILE_IO_ERROR;
            break;
        }
        nlohmann::json item;
        item[ServiceConstants::BACKUP_CERT_USER_ID_KEY] = userId;
        item[ServiceConstants::BACKUP_CERT_ALIAS_KEY] = fileName;
        item[ServiceConstants::BACKUP_CERT_CONTENT_KEY] = encoded;
        certsArray.push_back(item);
    }
    closedir(userDirHandle);
    return ret;
}

// Create the user dir for restore (owner foundation, same semantics as the EDM path).
ErrCode CreateUserDir(const std::string &userDir)
{
    CreateDirParam createDirParam;
    createDirParam.bundleDirScene = BundleDirScene::SERVICE_BMS_ENTERPRISE_CERT_DIR;
    ErrCode ret = InstalldClient::GetInstance()->Mkdir(userDir, S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH,
        Constants::FOUNDATION_UID, Constants::FOUNDATION_UID, createDirParam);
    if (ret != ERR_OK) {
        APP_LOGE("mkdir user dir failed, err: %{public}d", ret);
    }
    return ret;
}

// Clear certs in one user dir: capture into the snapshot first, then delete files and kernel keys.
ErrCode ClearUserCerts(const std::string &certRootDir, int32_t userId, LocalCertSnapshot &snapshot)
{
    std::string userDir = certRootDir + ServiceConstants::PATH_SEPARATOR + std::to_string(userId);
    DIR *userDirHandle = opendir(userDir.c_str());
    if (userDirHandle == nullptr) {
        APP_LOGE("opendir user dir failed, errno: %{public}d", errno);
        return ERR_APPEXECFWK_BACKUP_ENTERPRISE_CERT_RESTORE_FAILED;
    }
    ErrCode clearRet = ERR_OK;
    struct dirent *fileEntry = nullptr;
    while (clearRet == ERR_OK && (fileEntry = readdir(userDirHandle)) != nullptr) {
        if (fileEntry->d_type != DT_REG) {
            continue;
        }
        std::string fileName(fileEntry->d_name);
        if (!EndWith(fileName, ServiceConstants::CER_SUFFIX)) {
            continue;
        }
        CaptureLocalCert(certRootDir, userId, fileName, snapshot);
        ErrCode delRet = InstalldClient::GetInstance()->DeleteCertAndRemoveKey(
            {BuildCertFilePath(certRootDir, userId, fileName)});
        if (delRet != ERR_OK) {
            APP_LOGE("clear local cert failed, err: %{public}d", delRet);
            clearRet = ERR_APPEXECFWK_BACKUP_ENTERPRISE_CERT_RESTORE_FAILED;
        }
    }
    closedir(userDirHandle);
    return clearRet;
}

// Clear certs of the users involved in the backup; other local users' certs belong
// to their own backup sessions and stay untouched.
ErrCode ClearLocalCerts(const std::string &certRootDir, const std::set<int32_t> &userIdsToClear,
    LocalCertSnapshot &snapshot)
{
    ErrCode clearRet = ERR_OK;
    for (int32_t userId : userIdsToClear) {
        if (clearRet != ERR_OK) {
            break;
        }
        std::string userDir = certRootDir + ServiceConstants::PATH_SEPARATOR + std::to_string(userId);
        if (!IsDir(userDir)) {
            continue;
        }
        clearRet = ClearUserCerts(certRootDir, userId, snapshot);
    }
    return clearRet;
}

// Reinstall all certs in backup order; any failure triggers rollback.
ErrCode ReinstallCerts(const std::vector<CertItem> &items, const std::string &certRootDir,
    const LocalCertSnapshot &snapshot)
{
    std::vector<std::string> restoredPaths;
    for (const auto &item : items) {
        std::string userDir = certRootDir + ServiceConstants::PATH_SEPARATOR + std::to_string(item.userId);
        if (!IsDir(userDir) && CreateUserDir(userDir) != ERR_OK) {
            return RollbackRestoredCerts(restoredPaths, snapshot, certRootDir);
        }
        std::string certPath = BuildCertFilePath(certRootDir, item.userId, item.alias);
        if (certPath.size() > static_cast<size_t>(Constants::BMS_MAX_PATH_LENGTH)) {
            APP_LOGE("cert path too long, size: %{public}zu", certPath.size());
            return RollbackRestoredCerts(restoredPaths, snapshot, certRootDir);
        }
        ErrCode addRet = InstalldClient::GetInstance()->AddCertAndEnableKey(certPath, item.content);
        if (addRet != ERR_OK) {
            APP_LOGE("add cert and enable key failed, err: %{public}d", addRet);
            return RollbackRestoredCerts(restoredPaths, snapshot, certRootDir);
        }
        restoredPaths.push_back(certPath);
    }
    APP_LOGI("restore enterprise resign certs success, size: %{public}zu", items.size());
    return ERR_OK;
}
}  // namespace

ErrCode EnterpriseCertBackupHelper::BackupToJson(
    nlohmann::json &certsArray, const std::set<int32_t> &userIds, const std::string &certRootDir)
{
    std::lock_guard<std::mutex> lock(g_certBackupMutex);
    certsArray = nlohmann::json::array();
    ErrCode ret = ERR_OK;
    for (int32_t userId : userIds) {
        if (userId < Constants::START_USERID) {
            APP_LOGW("skip invalid userId: %{public}d", userId);
            continue;
        }
        std::string userDir = certRootDir + ServiceConstants::PATH_SEPARATOR + std::to_string(userId);
        if (!IsDir(userDir)) {
            // No cert dir for this user is normal (no cert ever delivered).
            continue;
        }
        ret = BackupUserCerts(userId, userDir, certsArray);
        if (ret != ERR_OK) {
            break;
        }
    }
    APP_LOGI("backup enterprise resign certs, size: %{public}zu", certsArray.size());
    return ret;
}

ErrCode EnterpriseCertBackupHelper::RestoreFromJson(
    const nlohmann::json &certsArray, const std::string &certRootDir)
{
    std::lock_guard<std::mutex> lock(g_certBackupMutex);
    std::vector<CertItem> items;
    ErrCode ret = ParseAndValidateCerts(certsArray, items);
    if (ret != ERR_OK) {
        return ret;
    }
    // 1. Clear local certs of the users present in the backup (delete files + remove
    //    kernel keys, same as the EDM Delete API); capture contents into a snapshot
    //    first for rollback.
    std::set<int32_t> userIdsToClear;
    for (const auto &item : items) {
        userIdsToClear.insert(item.userId);
    }
    LocalCertSnapshot snapshot;
    if (IsDir(certRootDir)) {
        ret = ClearLocalCerts(certRootDir, userIdsToClear, snapshot);
        if (ret != ERR_OK) {
            // Clear phase failed: roll back cleared certs (snapshot reinstall), keep no zero-cert state.
            return RollbackRestoredCerts({}, snapshot, certRootDir);
        }
    }
    // 2. Reinstall in backup order: write files + re-enable kernel keys.
    return ReinstallCerts(items, certRootDir, snapshot);
}
}  // namespace AppExecFwk
}  // namespace OHOS
