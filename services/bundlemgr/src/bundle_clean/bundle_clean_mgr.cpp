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

#include "bundle_clean_mgr.h"

#include "app_log_wrapper.h"
#include "appexecfwk_errors.h"
#include "bms_rdb_config.h"
#include "bundle_service_constants.h"
#include "errors.h"
#include "rdb_data_manager.h"
#include "boot_detector_hiview.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
// Keep in sync with FINGERPRINT in bundle_mgr_service_event_handler.cpp.
const std::string FINGERPRINT_KEY = "fingerprint";
// Keep in sync with BMS_PARAM_TABLE_NAME in bms_param.cpp.
const std::string BMS_PARAM_TABLE_NAME = "bms_param";
// Cleanup recovery flag: written by OnClean, read and cleared by event_handler on normal boot.
const std::string CLEANUP_RECOVERY_FLAG_KEY = "bmsCleanRecovery";
const std::string CLEANUP_RECOVERY_FLAG_VALUE = "true";
}  // namespace

BundleCleanMgr::BundleCleanMgr() {}

BundleCleanMgr::~BundleCleanMgr() {}

ErrCode BundleCleanMgr::OnClean()
{
    APP_LOGI("BundleCleanMgr OnClean start");
    ErrCode ret = CleanFingerprint();
    if (ret != ERR_OK) {
        APP_LOGE("BOPD clean: clean fingerprint failed, err is %{public}d.", ret);
        return ret;
    }
    ret = SetCleanupRecoveryFlag();
    if (ret != ERR_OK) {
        APP_LOGE("BOPD clean: set cleanup recovery flag failed, err is %{public}d.", ret);
        return ret;
    }
    APP_LOGI("BundleCleanMgr OnClean end");
    return ERR_OK;
}

ErrCode BundleCleanMgr::CleanFingerprint()
{
    auto rdbDataManager = CreateMirrorRdbDataManager(BMS_PARAM_TABLE_NAME);
    if (rdbDataManager == nullptr) {
        APP_LOGE("BOPD clean: create mirror rdb data manager failed");
        return ERR_APPEXECFWK_NULL_PTR;
    }
    // DeleteData is idempotent: a missing row returns true (no-op).
    // Delete the row only; do not write an empty value, drop the table, delete the db file, or touch other rows.
    if (!rdbDataManager->DeleteData(FINGERPRINT_KEY)) {
        APP_LOGE("BOPD clean: delete fingerprint row failed");
        return ERR_APPEXECFWK_DB_SQL_GENERIC_ERROR;
    }
    APP_LOGI("BOPD clean: fingerprint row deleted on mirror bmsdb");
    return ERR_OK;
}

ErrCode BundleCleanMgr::SetCleanupRecoveryFlag()
{
    auto rdbDataManager = CreateMirrorRdbDataManager(BMS_PARAM_TABLE_NAME);
    if (rdbDataManager == nullptr) {
        APP_LOGE("BOPD clean: create mirror rdb data manager failed");
        return ERR_APPEXECFWK_NULL_PTR;
    }
    // Write the flag; read by event_handler on normal boot to force pre-install same-version reinstall.
    // InsertData matches SaveBmsParam semantics and is idempotent for an existing key.
    if (!rdbDataManager->InsertData(CLEANUP_RECOVERY_FLAG_KEY, CLEANUP_RECOVERY_FLAG_VALUE)) {
        APP_LOGE("BOPD clean: set cleanup recovery flag failed");
        return ERR_APPEXECFWK_DB_SQL_GENERIC_ERROR;
    }
    APP_LOGI("BOPD clean: cleanup recovery flag set on mirror bmsdb");
    return ERR_OK;
}

std::shared_ptr<RdbDataManager> BundleCleanMgr::CreateMirrorRdbDataManager(const std::string &tableName)
{
    // Use an isolated RdbDataManager with the mirror dbPath, separate from the BmsParam/BundleDataStorageRdb
    // singletons used on the normal boot path. Derive the mirror path via BootDetectorReplaceDataPrefix
    // and never fall back to a hardcoded path.
    const std::string &srcPath = ServiceConstants::BUNDLE_MANAGER_SERVICE_PATH;
    // BootDetectorReplaceDataPrefix replaces the /data prefix with the mirror prefix; on failure it
    // returns the original path unchanged, so treat an unchanged result as failure (return nullptr,
    // let the framework retry; do not fall back to a hardcoded path).
    std::string mirrorPath = OHOS::HiviewDFX::BootDetectorReplaceDataPrefix(srcPath);
    if (mirrorPath == srcPath) {
        APP_LOGE("BOPD clean: BootDetectorReplaceDataPrefix returned unchanged path=%{public}s",
            srcPath.c_str());
        return nullptr;
    }
    BmsRdbConfig config;
    config.dbPath = mirrorPath;
    config.dbName = ServiceConstants::BUNDLE_RDB_NAME;  // "/bmsdb.db"
    config.tableName = tableName;  // bms_param
    auto rdbDataManager = std::make_shared<RdbDataManager>(config);
    if (rdbDataManager == nullptr) {
        APP_LOGE("BOPD clean: make shared RdbDataManager failed");
        return nullptr;
    }
    // CreateTable is idempotent (CREATE TABLE IF NOT EXISTS); ensures the target table exists for operation.
    rdbDataManager->CreateTable();
    return rdbDataManager;
}
}  // namespace AppExecFwk
}  // namespace OHOS
