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

#include "quick_fix_manager_host_impl.h"

#include "app_log_wrapper.h"
#include "bundle_constants.h"
#include "bundle_permission_mgr.h"
#include "bundle_util.h"
#include "quick_fix_data_mgr.h"

namespace OHOS {
namespace AppExecFwk {
QuickFixManagerHostImpl::QuickFixManagerHostImpl()
{
    APP_LOGI("create QuickFixManagerHostImpl");
    Init();
}

QuickFixManagerHostImpl::~QuickFixManagerHostImpl()
{
    APP_LOGI("destory QuickFixManagerHostImpl");
}

void QuickFixManagerHostImpl::Init()
{
    APP_LOGI("Init begin");
    auto quickFixerRunner = EventRunner::Create(Constants::QUICK_FIX_MGR);
    if (!quickFixerRunner) {
        APP_LOGE("create quickFixer runner fail");
        return;
    }
    quickFixAsyncMgr_ = std::make_shared<QuickFixAsyncMgr>(quickFixerRunner);
}

bool QuickFixManagerHostImpl::DeployQuickFix(const std::vector<std::string> &bundleFilePaths,
    const sptr<IQuickFixStatusCallback> &statusCallback)
{
    APP_LOGI("QuickFixManagerHostImpl::DeployQuickFix start");
    if (bundleFilePaths.empty() || (statusCallback == nullptr)) {
        APP_LOGE("QuickFixManagerHostImpl::DeployQuickFix wrong parms");
        return false;
    }
    if (quickFixAsyncMgr_ == nullptr) {
        APP_LOGE("QuickFixManagerHostImpl::DeployQuickFix quickFixerAsyncMgr is nullptr");
        return false;
    }

    return quickFixAsyncMgr_->DeployQuickFix(bundleFilePaths, statusCallback);
}

bool QuickFixManagerHostImpl::SwitchQuickFix(const std::string &bundleName,
    const sptr<IQuickFixStatusCallback> &statusCallback)
{
    APP_LOGI("QuickFixManagerHostImpl::SwitchQuickFix start");
    if (bundleName.empty() || (statusCallback == nullptr)) {
        APP_LOGE("QuickFixManagerHostImpl::SwitchQuickFix wrong parms");
        return false;
    }
    if (quickFixAsyncMgr_ == nullptr) {
        APP_LOGE("QuickFixManagerHostImpl::DeployQuickFix quickFixerAsyncMgr is nullptr");
        return false;
    }

    return quickFixAsyncMgr_->SwitchQuickFix(bundleName, statusCallback);
}

bool QuickFixManagerHostImpl::DeleteQuickFix(const std::string &bundleName,
    const sptr<IQuickFixStatusCallback> &statusCallback)
{
    APP_LOGI("QuickFixManagerHostImpl::DeleteQuickFix start");
    if (bundleName.empty() || (statusCallback == nullptr)) {
        APP_LOGE("QuickFixManagerHostImpl::DeleteQuickFix wrong parms");
        return false;
    }
    if (quickFixAsyncMgr_ == nullptr) {
        APP_LOGE("QuickFixManagerHostImpl::DeployQuickFix quickFixerAsyncMgr is nullptr");
        return false;
    }

    return quickFixAsyncMgr_->DeleteQuickFix(bundleName, statusCallback);
}

bool QuickFixManagerHostImpl::CreateFd(const std::string &fileName, int32_t &fd, std::string &path)
{
    APP_LOGD("QuickFixManagerHostImpl::CreateFd start.");
    if (!BundlePermissionMgr::VerifyCallingPermission(Constants::PERMISSION_INSTALL_BUNDLE)) {
        APP_LOGE("verify install permission failed.");
        return false;
    }
    if (!BundleUtil::CheckFileType(fileName, Constants::QUICK_FIX_FILE_SUFFIX)) {
        APP_LOGE("not quick fix file.");
        return false;
    }
    std::string tmpDir = BundleUtil::CreateInstallTempDir(++id_, true);
    if (tmpDir.empty()) {
        APP_LOGE("create tmp dir failed.");
        return false;
    }
    path = tmpDir + fileName;
    if ((fd = BundleUtil::CreateFileDescriptor(path, 0)) < 0) {
        APP_LOGE("create file descriptor failed.");
        return false;
    }
    return true;
}
}
} // namespace OHOS
