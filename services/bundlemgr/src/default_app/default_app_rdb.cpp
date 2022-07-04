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

#include "default_app_rdb.h"

#include "app_log_wrapper.h"

namespace OHOS {
namespace AppExecFwk {
DefaultAppRdb::DefaultAppRdb()
{
    APP_LOGD("create DefaultAppRdb.");
}

DefaultAppRdb::~DefaultAppRdb()
{
    APP_LOGD("destroy DefaultAppRdb.");
}

bool DefaultAppRdb::GetDefaultApplicationInfos(int32_t userId, std::map<std::string, Element>& infos)
{
    APP_LOGD("begin to GetDefaultApplicationInfos, userId : %{public}d.", userId);
    return true;
}

bool DefaultAppRdb::GetDefaultApplicationInfo(int32_t userId, const std::string& type, Element& element)
{
    APP_LOGD("begin to GetDefaultApplicationInfo, userId : %{public}d, type : %{public}s.", userId, type.c_str());
    return true;
}

bool DefaultAppRdb::SetDefaultApplicationInfos(int32_t userId, const std::map<std::string, Element>& infos)
{
    APP_LOGD("begin to SetDefaultApplicationInfos, userId : %{public}d.", userId);
    return true;
}

bool DefaultAppRdb::SetDefaultApplicationInfo(int32_t userId, const std::string& type, const Element& element)
{
    APP_LOGD("begin to SetDefaultApplicationInfo, userId : %{public}d, type : %{public}s.", userId, type.c_str());
    return true;
}

bool DefaultAppRdb::DeleteDefaultApplicationInfos(int32_t userId)
{
    APP_LOGD("begin to DeleteDefaultApplicationInfos, userId : %{public}d.", userId);
    return true;
}

bool DefaultAppRdb::DeleteDefaultApplicationInfo(int32_t userId, const std::string& type)
{
    APP_LOGD("begin to DeleteDefaultApplicationInfo, userId : %{public}d, type : %{public}s.", userId, type.c_str());
    return true;
}

void DefaultAppRdb::RegisterDeathListener()
{
    APP_LOGD("RegisterDeathListener.");
}

void DefaultAppRdb::UnRegisterDeathListener()
{
    APP_LOGD("UnRegisterDeathListener.");
}
}
}
