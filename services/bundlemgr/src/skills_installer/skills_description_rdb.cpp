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

#include "skills_description_rdb.h"
#include "app_log_wrapper.h"
#include "bundle_constants.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
constexpr const char* SKILLS_DESCRIPTION_TABLE_NAME = "skills_description";
// skills description table columns
constexpr const char* BUNDLE_NAME = "BUNDLE_NAME";
constexpr const char* MODULE_NAME = "MODULE_NAME";
constexpr const char* SKILL_NAME = "SKILL_NAME";
constexpr const char* DESCRIPTION = "DESCRIPTION";

constexpr int8_t INDEX_BUNDLE_NAME = 0;
constexpr int8_t INDEX_MODULE_NAME = 1;
constexpr int8_t INDEX_SKILL_NAME = 2;
constexpr int8_t INDEX_DESCRIPTION = 3;
}

SkillsDescriptionRdb::SkillsDescriptionRdb()
{
    APP_LOGD("create SkillsDescriptionRdb");
    BmsRdbConfig bmsRdbConfig;
    bmsRdbConfig.dbName = ServiceConstants::BUNDLE_RDB_NAME;
    std::string skillsDescriptionTableName = SKILLS_DESCRIPTION_TABLE_NAME;
    bmsRdbConfig.tableName = skillsDescriptionTableName;
    bmsRdbConfig.createTableSql = std::string(
        "CREATE TABLE IF NOT EXISTS "
        + skillsDescriptionTableName
        + "(BUNDLE_NAME TEXT NOT NULL, "
        + "MODULE_NAME TEXT NOT NULL, "
        + "SKILL_NAME TEXT NOT NULL, "
        + "DESCRIPTION TEXT, "
        + "PRIMARY KEY(BUNDLE_NAME, MODULE_NAME, SKILL_NAME));");
    rdbDataManager_ = std::make_shared<RdbDataManager>(bmsRdbConfig);
    rdbDataManager_->CreateTable();
}

SkillsDescriptionRdb::~SkillsDescriptionRdb()
{
    APP_LOGD("destroy SkillsDescriptionRdb");
}

ErrCode SkillsDescriptionRdb::AddSkillDescriptions(const std::vector<SkillsPackageInfo> &skillInfoList)
{
    if (skillInfoList.empty()) {
        APP_LOGE("AddSkillDescriptions failed, skillInfoList is empty");
        return ERR_APPEXECFWK_INSTALL_PARAM_ERROR;
    }

    std::vector<NativeRdb::ValuesBucket> valuesBucketList;
    for (const auto &skillInfo : skillInfoList) {
        if (skillInfo.bundleName.empty() || skillInfo.moduleName.empty() || skillInfo.skillsName.empty()) {
            APP_LOGE("AddSkillDescriptions failed, bundleName or moduleName or skillsName is empty");
            continue;
        }

        NativeRdb::ValuesBucket valuesBucket;
        valuesBucket.PutString(BUNDLE_NAME, skillInfo.bundleName);
        valuesBucket.PutString(MODULE_NAME, skillInfo.moduleName);
        valuesBucket.PutString(SKILL_NAME, skillInfo.skillsName);
        valuesBucket.PutString(DESCRIPTION, skillInfo.description);
        valuesBucketList.push_back(valuesBucket);
    }

    if (valuesBucketList.empty()) {
        APP_LOGE("AddSkillDescriptions failed, no valid skillInfo to insert");
        return ERR_APPEXECFWK_INSTALL_PARAM_ERROR;
    }

    int64_t insertNum = 0;
    if (!rdbDataManager_->BatchInsert(insertNum, valuesBucketList)) {
        APP_LOGE("AddSkillDescriptions failed, BatchInsertData returned false");
        return ERR_APPEXECFWK_DB_BATCH_INSERT_ERROR;
    }
    if (valuesBuckets.size() != static_cast<uint64_t>(insertNum)) {
        APP_LOGE("BatchInsert size not expected");
        return ERR_APPEXECFWK_DB_BATCH_INSERT_ERROR;
    }

    return ERR_OK;
}

ErrCode SkillsDescriptionRdb::DeleteSkillDescriptions(const std::string &bundleName)
{
    if (bundleName.empty()) {
        APP_LOGE("DeleteSkillDescriptions failed, bundleName is empty");
        return ERR_APPEXECFWK_INSTALL_PARAM_ERROR;
    }

    NativeRdb::AbsRdbPredicates absRdbPredicates(SKILLS_DESCRIPTION_TABLE_NAME);
    absRdbPredicates.EqualTo(BUNDLE_NAME, bundleName);
    if (!rdbDataManager_->DeleteData(absRdbPredicates)) {
        APP_LOGE("DeleteSkillDescriptions failed, DeleteData returned false");
        return ERR_APPEXECFWK_DB_DELETE_ERROR;
    }
    return ERR_OK;
}

ErrCode SkillsDescriptionRdb::DeleteSkillDescriptions(const std::string &bundleName, const std::string &moduleName)
{
    if (bundleName.empty() || moduleName.empty()) {
        APP_LOGE("DeleteSkillDescriptions failed, bundleName or moduleName is empty");
        return ERR_APPEXECFWK_INSTALL_PARAM_ERROR;
    }

    NativeRdb::AbsRdbPredicates absRdbPredicates(SKILLS_DESCRIPTION_TABLE_NAME);
    absRdbPredicates.EqualTo(BUNDLE_NAME, bundleName)
    absRdbPredicates.EqualTo(MODULE_NAME, moduleName);
    if (!rdbDataManager_->DeleteData(absRdbPredicates)) {
        APP_LOGE("DeleteSkillDescriptions failed, DeleteData returned false");
        return ERR_APPEXECFWK_DB_DELETE_ERROR;
    }
    return ERR_OK;
}

ErrCode SkillsDescriptionRdb::DeleteSkillDescriptions(const std::string &bundleName,
    const std::string &moduleName, const std::string &skillName)
{
    if (bundleName.empty() || moduleName.empty() || skillName.empty()) {
        APP_LOGE("DeleteSkillDescriptions failed, bundleName or moduleName or skillName is empty");
        return ERR_APPEXECFWK_INSTALL_PARAM_ERROR;
    }

    NativeRdb::AbsRdbPredicates absRdbPredicates(SKILLS_DESCRIPTION_TABLE_NAME);
    absRdbPredicates.EqualTo(BUNDLE_NAME, bundleName)
    absRdbPredicates.EqualTo(MODULE_NAME, moduleName)
    absRdbPredicates.EqualTo(SKILL_NAME, skillName);
    if (!rdbDataManager_->DeleteData(absRdbPredicates)) {
        APP_LOGE("DeleteSkillDescriptions failed, DeleteData returned false");
        return ERR_APPEXECFWK_DB_DELETE_ERROR;
    }
    return ERR_OK;
}
} // namespace AppExecFwk
} // namespace OHOS
