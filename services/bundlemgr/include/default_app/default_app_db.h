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

#ifndef FOUNDATION_DEFAULT_APPLICATION_FRAMEWORK_DEFAULT_APP_DB
#define FOUNDATION_DEFAULT_APPLICATION_FRAMEWORK_DEFAULT_APP_DB

#include <map>

#include "bundle_constants.h"
#include "default_app_data.h"
#include "distributed_kv_data_manager.h"
#include "element.h"
#include "inner_bundle_info.h"

namespace OHOS {
namespace AppExecFwk {
class DefaultAppDb {
public:
    DefaultAppDb();
    ~DefaultAppDb();
    bool GetDefaultApplicationInfos(int32_t userId, std::map<std::string, Element>& infos);
    bool GetDefaultApplicationInfo(int32_t userId, const std::string& type, Element& element);
    bool SetDefaultApplicationInfos(int32_t userId, const std::map<std::string, Element>& infos);
    bool SetDefaultApplicationInfo(int32_t userId, const std::string& type, const Element& element);
    bool DeleteDefaultApplicationInfos(int32_t userId);
    bool DeleteDefaultApplicationInfo(int32_t userId, const std::string& type);
private:
    void Init();
    bool OpenKvDb();
    bool GetDataFromDb(int32_t userId, std::map<std::string, Element>& infos);
    bool SaveDataToDb(int32_t userId, const std::map<std::string, Element>& infos);
    bool DeleteDataFromDb(int32_t userId);

    const DistributedKv::AppId appId_ { Constants::APP_ID };
    const DistributedKv::StoreId storeId_ { Constants::DEFAULT_APP_DATA_STORE_ID };
    DistributedKv::DistributedKvDataManager dataManager_;
    std::shared_ptr<DistributedKv::SingleKvStore> kvStorePtr_;
};
}
}
#endif
