/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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

#include "bundle_exception_handler.h"

#include "installd_client.h"

namespace OHOS {
namespace AppExecFwk {
BundleExceptionHandler::BundleExceptionHandler(const std::shared_ptr<IBundleDataStorage> &dataStorage)
    : dataStorage_(dataStorage)
{
    APP_LOGD("create bundle excepetion handler instance");
}

BundleExceptionHandler::~BundleExceptionHandler()
{
    APP_LOGD("destroy bundle excepetion handler instance");
}


void BundleExceptionHandler::HandleInvalidBundle(InnerBundleInfo &info, bool &isBundleValid)
{
    std::string appCodePath = Constants::BUNDLE_CODE_DIR + ServiceConstants::PATH_SEPARATOR + info.GetBundleName();
    if (!IsBundleHapPathExist(info)) {
        RemoveBundleAndDataDir(appCodePath, info.GetBundleName(), info.GetUserId());
        DeleteBundleInfoFromStorage(info);
        isBundleValid = false;
        return;
    }
    InnerHandleInvalidBundle(info, isBundleValid);
}

bool BundleExceptionHandler::RemoveBundleAndDataDir(const std::string &bundleDir,
    const std::string &bundleOrMoudleDir, int32_t userId) const
{
    ErrCode result = InstalldClient::GetInstance()->RemoveDir(bundleDir);
    if (result != ERR_OK) {
        APP_LOGE("fail to remove bundle dir %{public}s, error is %{public}d", bundleDir.c_str(), result);
        return false;
    }

    if (bundleOrMoudleDir.find(ServiceConstants::HAPS) != std::string::npos) {
        result = InstalldClient::GetInstance()->RemoveModuleDataDir(bundleOrMoudleDir, userId);
        if (result != ERR_OK) {
            APP_LOGE("fail to remove module data dir %{public}s, error is %{public}d", bundleOrMoudleDir.c_str(),
                result);
            return false;
        }
    } else {
        result = InstalldClient::GetInstance()->RemoveBundleDataDir(bundleOrMoudleDir, userId);
        if (result != ERR_OK) {
            APP_LOGE("fail to remove bundle data dir %{public}s, error is %{public}d", bundleOrMoudleDir.c_str(),
                result);
            return false;
        }
    }
    return true;
}

void BundleExceptionHandler::DeleteBundleInfoFromStorage(const InnerBundleInfo &info)
{
    auto storage = dataStorage_.lock();
    if (storage) {
        APP_LOGD("remove bundle info of %{public}s from the storage", info.GetBundleName().c_str());
        storage->DeleteStorageBundleInfo(info);
    } else {
        APP_LOGE(" fail to remove bundle info of %{public}s from the storage", info.GetBundleName().c_str());
    }
}

bool BundleExceptionHandler::IsBundleHapPathExist(const InnerBundleInfo &info)
{
    if (info.IsPreInstallApp() || (info.GetApplicationBundleType() != BundleType::APP)) {
        APP_LOGD("bundleName:%{public}s no need to check", info.GetBundleName().c_str());
        return true;
    }
    APP_LOGD("start, need to check bundleName:%{public}s hap file", info.GetBundleName().c_str());
    const auto innerModuleInfos = info.GetInnerModuleInfos();
    for (const auto &item : innerModuleInfos) {
        if (!item.second.hapPath.empty()) {
            bool isExist = false;
            if (InstalldClient::GetInstance()->IsExistFile(item.second.hapPath, isExist) != ERR_OK) {
                APP_LOGW("bundleName:%{public}s check hap path failed", info.GetBundleName().c_str());
                continue;
            }
            if (!isExist) {
                APP_LOGE("bundleName:%{public}s hap Path is not exist", info.GetBundleName().c_str());
                return false;
            }
        }
    }
    return true;
}

void BundleExceptionHandler::InnerHandleInvalidBundle(InnerBundleInfo &info, bool &isBundleValid)
{
    auto mark = info.GetInstallMark();
    if (mark.status == InstallExceptionStatus::INSTALL_FINISH) {
        return;
    }
    APP_LOGI_NOFUNC("%{public}s status is %{public}d", info.GetBundleName().c_str(), mark.status);
    std::string appCodePath = Constants::BUNDLE_CODE_DIR + ServiceConstants::PATH_SEPARATOR + info.GetBundleName();
    auto moduleDir = appCodePath + ServiceConstants::PATH_SEPARATOR + mark.packageName;
    auto moduleDataDir = info.GetBundleName() + ServiceConstants::HAPS + mark.packageName;

    // install and update failed before service restart
    if (mark.status == InstallExceptionStatus::INSTALL_START) {
        // unable to distinguish which user failed the installation
        (void)RemoveBundleAndDataDir(appCodePath, info.GetBundleName(), info.GetUserId());
        DeleteBundleInfoFromStorage(info);
        isBundleValid = false;
    } else if (mark.status == InstallExceptionStatus::UPDATING_EXISTED_START) {
        if (InstalldClient::GetInstance()->RemoveDir(moduleDir + ServiceConstants::TMP_SUFFIX) == ERR_OK) {
            info.SetBundleStatus(InnerBundleInfo::BundleStatus::ENABLED);
        }
    } else if (mark.status == InstallExceptionStatus::UPDATING_NEW_START &&
        RemoveBundleAndDataDir(moduleDir, moduleDataDir, info.GetUserId())) {
        info.SetBundleStatus(InnerBundleInfo::BundleStatus::ENABLED);
    } else if (mark.status == InstallExceptionStatus::UNINSTALL_BUNDLE_START &&
        RemoveBundleAndDataDir(appCodePath, info.GetBundleName(), info.GetUserId())) {  // continue to uninstall
        DeleteBundleInfoFromStorage(info);
        isBundleValid = false;
    } else if (mark.status == InstallExceptionStatus::UNINSTALL_PACKAGE_START) {
        if (info.IsOnlyModule(mark.packageName) &&
            RemoveBundleAndDataDir(appCodePath, info.GetBundleName(), info.GetUserId())) {
            DeleteBundleInfoFromStorage(info);
            isBundleValid = false;
            return;
        }
        if (RemoveBundleAndDataDir(moduleDir, moduleDataDir, info.GetUserId())) {
            info.RemoveModuleInfo(mark.packageName);
            info.SetBundleStatus(InnerBundleInfo::BundleStatus::ENABLED);
        }
    } else if (mark.status == InstallExceptionStatus::UPDATING_FINISH) {
        if (InstalldClient::GetInstance()->RenameModuleDir(moduleDir + ServiceConstants::TMP_SUFFIX, moduleDir) !=
            ERR_OK) {
            APP_LOGI_NOFUNC("%{public}s rename module failed, may not exist", info.GetBundleName().c_str());
        }
    }
}
}  // namespace AppExecFwkConstants
}  // namespace OHOS