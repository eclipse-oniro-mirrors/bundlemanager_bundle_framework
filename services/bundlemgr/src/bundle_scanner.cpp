/*
 * Copyright (c) 2021-2025 Huawei Device Co., Ltd.
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

#include "bundle_scanner.h"

#include <dirent.h>

#include "bundle_mgr_service.h"
#include "hitrace_meter.h"
#include "datetime_ex.h"
#include "perf_profile.h"

namespace OHOS {
namespace AppExecFwk {

BundleScanner::BundleScanner()
{
    APP_LOGI("instance is created");
}

BundleScanner::~BundleScanner()
{
    APP_LOGI("instance is destroyed");
}

const std::list<std::string> &BundleScanner::Scan(const std::string &dirPath)
{
    HITRACE_METER_NAME_EX(HITRACE_LEVEL_INFO, HITRACE_TAG_APP, __PRETTY_FUNCTION__, nullptr);
    PerfProfile::GetInstance().SetBundleScanStartTime(GetTickCount());

    APP_LOGD("path:%{private}s", dirPath.c_str());
    if (!dirPath.empty()) {
        if (!ScanImpl(dirPath)) {
            APP_LOGW("BundleScanner::Scan scan error");
        }
    }

    APP_LOGD("scan result num:%{public}zu", entries_.size());
    for (const auto &item : entries_) {
        APP_LOGD("app item:%{private}s", item.c_str());
    }

    PerfProfile::GetInstance().SetBundleScanEndTime(GetTickCount());
    return entries_;
}

bool BundleScanner::ScanImpl(const std::string &dirPath)
{
    DIR *dirp = opendir(dirPath.c_str());
    if (dirp == nullptr) {
        APP_LOGE("BundleScanner::ScanImpl open dir:%{private}s fail, errno:%{public}d", dirPath.c_str(), errno);
        return false;
    }

    struct dirent *dirent = nullptr;
    for (;;) {
        dirent = readdir(dirp);
        if (dirent == nullptr) {
            APP_LOGD("fail readdir err:%{public}d", errno);
            break;
        }

        std::string currentName(dirent->d_name);
        APP_LOGD("folder found:'%{private}s'", dirent->d_name);
        if (currentName.compare(".") == 0 || currentName.compare("..") == 0) {
            continue;
        }
        entries_.push_back(dirPath + ServiceConstants::PATH_SEPARATOR + currentName);
    }

    if (closedir(dirp) == -1) {
        APP_LOGW("close dir fail, errno:%{public}d", errno);
    }
    return true;
}

}  // namespace AppExecFwk
}  // namespace OHOS
