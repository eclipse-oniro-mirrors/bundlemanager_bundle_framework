/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#ifndef FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_MIME_TYPE_RDB_H
#define FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_MIME_TYPE_RDB_H

#include <string>
#include <utility>
#include <vector>

#include "rdb_data_manager.h"

namespace OHOS {
namespace AppExecFwk {
class MimeTypeRdb {
public:
    MimeTypeRdb();
    ~MimeTypeRdb();
    bool SetExtNameOrMimeTypeToAbility(const std::string &bundleName, const std::string &modudleName,
        const std::string &abilityName, const std::string &extName, const std::string &mimeType);
    bool DelExtNameOrMimeTypeToAbility(const std::string &bundleName, const std::string &modudleName,
        const std::string &abilityName, const std::string &extName, const std::string &mimeType);
    bool GetExtAndTypeByAbility(const std::string &bundleName, const std::string &modudleName,
        const std::string &abilityName, std::vector<std::pair<std::string, std::string>> extAndTypes);

private:
    std::shared_ptr<RdbDataManager> rdbDataManager_;

#define CHECK_RDB_RESULT_RETURN_IF_FAIL(errcode, errmsg)                           \
    do {                                                                           \
        if ((errcode) != NativeRdb::E_OK) {                                          \
            APP_LOGE(errmsg, errcode);                                             \
            return false;                                                          \
        }                                                                          \
    } while (0)
};
}
}
#endif