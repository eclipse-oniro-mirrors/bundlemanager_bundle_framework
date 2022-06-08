/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include "default_app_db.h"

namespace OHOS {
namespace AppExecFwk {
DefaultAppDb::DefaultAppDb()
{
    APP_LOGD("create DefaultAppDb.");
    OpenKvDb();
}

DefaultAppDb::~DefaultAppDb()
{
    APP_LOGD("destroy DefaultAppDb.");
    dataManager_.CloseKvStore(appId_, kvStorePtr_);
}

bool DefaultAppDb::OpenKvDb()
{
    return false;
}

bool DefaultAppDb::GetDataFromDb(int32_t userId, std::map<std::string, Element>& infos)
{
    return false;
}

bool DefaultAppDb::SaveDataToDb(int32_t userId, const std::map<std::string, Element>& infos)
{
    return false;
}

bool DefaultAppDb::DeleteDataFromDb(int32_t userId)
{
    return false;
}

bool DefaultAppDb::GetDefaultApplicationInfos(int32_t userId, std::map<std::string, Element>& infos)
{
    return false;
}

bool DefaultAppDb::GetDefaultApplicationInfo(int32_t userId, const std::string& type, Element& element)
{
    return false;
}

bool DefaultAppDb::SetDefaultApplicationInfos(int32_t userId, const std::map<std::string, Element>& infos)
{
    return false;
}

bool DefaultAppDb::SetDefaultApplicationInfo(int32_t userId, const std::string& type, const Element& element)
{
    return false;
}

bool DefaultAppDb::DeleteDefaultApplicationInfos(int32_t userId)
{
    return false;
}

bool DefaultAppDb::DeleteDefaultApplicationInfo(int32_t userId, const std::string& type)
{
    return false;
}
}
}
