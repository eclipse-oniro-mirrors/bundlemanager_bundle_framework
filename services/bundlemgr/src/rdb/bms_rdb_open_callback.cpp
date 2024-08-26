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

#include "bms_rdb_open_callback.h"

#include "app_log_wrapper.h"

#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <cerrno>

#define BMS_MONITOR_FL 0x00000002
#define BMS_IOCTL_GET_FLAGS _IOR(0xf5, 70, unsigned int)
#define BMS_IOCTL_SET_FLAGS _IOR(0xf5, 71, unsigned int)

namespace OHOS {
namespace AppExecFwk {
BmsRdbOpenCallback::BmsRdbOpenCallback(const BmsRdbConfig &bmsRdbConfig)\
    : bmsRdbConfig_(bmsRdbConfig) {}

int32_t BmsRdbOpenCallback::OnCreate(NativeRdb::RdbStore &rdbStore)
{
    APP_LOGI("OnCreate");

    int32_t fd = open((bmsRdbConfig_.dbPath + bmsRdbConfig_.dbName).c_str(), O_RDWR, 0777);
    if (fd < 0) {
        APP_LOGW("Failed to open file");
        return NativeRdb::E_OK;
    }
    unsigned int flags = 0;
    if (ioctl(fd, BMS_IOCTL_GET_FLAGS, &flags) < 0) {
        APP_LOGW("Failed to get flags, errno:%{public}d", errno);
        return NativeRdb::E_OK;
    }
    flags |= BMS_MONITOR_FL;
    if (ioctl(fd, BMS_IOCTL_SET_FLAGS, &flags) < 0) {
        APP_LOGW("Failed to set flags, errno:%{public}d", errno);
        return NativeRdb::E_OK;
    }
    APP_LOGI("Set delete monitor success");
    return NativeRdb::E_OK;
}

int32_t BmsRdbOpenCallback::OnUpgrade(
    NativeRdb::RdbStore &rdbStore, int currentVersion, int targetVersion)
{
    APP_LOGI("OnUpgrade currentVersion: %{plubic}d, targetVersion: %{plubic}d",
        currentVersion, targetVersion);
    return NativeRdb::E_OK;
}

int32_t BmsRdbOpenCallback::OnDowngrade(
    NativeRdb::RdbStore &rdbStore, int currentVersion, int targetVersion)
{
    APP_LOGI("OnDowngrade  currentVersion: %{plubic}d, targetVersion: %{plubic}d",
        currentVersion, targetVersion);
    return NativeRdb::E_OK;
}

int32_t BmsRdbOpenCallback::OnOpen(NativeRdb::RdbStore &rdbStore)
{
    APP_LOGI("OnOpen");
    return NativeRdb::E_OK;
}

int32_t BmsRdbOpenCallback::onCorruption(std::string databaseFile)
{
    APP_LOGI("onCorruption");
    return NativeRdb::E_OK;
}
}  // namespace AppExecFwk
}  // namespace OHOS
