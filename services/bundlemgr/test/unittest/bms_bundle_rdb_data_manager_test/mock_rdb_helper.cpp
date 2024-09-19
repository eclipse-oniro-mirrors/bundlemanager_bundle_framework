/*
 * Copyright (C) 2024 Huawei Device Co., Ltd.
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

#include "rdb_helper.h"

namespace {
    static std::shared_ptr<OHOS::NativeRdb::RdbStore> g_mockRdbStore = nullptr;
}

void MockGetRdbStore(std::shared_ptr<OHOS::NativeRdb::RdbStore> mockRdbStore)
{
    g_mockRdbStore = mockRdbStore;
}

namespace OHOS {
namespace NativeRdb {
std::shared_ptr<RdbStore> RdbHelper::GetRdbStore(
    const RdbStoreConfig& config, int version, RdbOpenCallback& openCallback, int& errCode)
{
    return g_mockRdbStore;
}
}
}