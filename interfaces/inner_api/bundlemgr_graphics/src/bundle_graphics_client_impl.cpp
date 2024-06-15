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

#include "bundle_graphics_client_impl.h"

#include <unistd.h>

#include "app_log_wrapper.h"
#include "bundle_constants.h"
#include "bundle_file_util.h"
#include "bundle_mgr_interface.h"
#include "bundle_mgr_proxy.h"
#include "image_source.h"
#include "if_system_ability_manager.h"
#include "iservice_registry.h"
#include "system_ability_definition.h"

namespace OHOS {
namespace AppExecFwk {
sptr<IBundleMgr> BundleGraphicsClientImpl::GetBundleMgr()
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (bundleMgr_ == nullptr) {
        auto systemAbilityManager = OHOS::SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
        if (systemAbilityManager == nullptr) {
            APP_LOGE("GetBundleMgr GetSystemAbilityManager is null");
            return nullptr;
        }
        auto bundleMgrSa = systemAbilityManager->GetSystemAbility(OHOS::BUNDLE_MGR_SERVICE_SYS_ABILITY_ID);
        if (bundleMgrSa == nullptr) {
            APP_LOGE("GetBundleMgr GetSystemAbility is null");
            return nullptr;
        }
        auto bundleMgr = OHOS::iface_cast<IBundleMgr>(bundleMgrSa);
        if (bundleMgr == nullptr) {
            APP_LOGE("GetBundleMgr iface_cast get null");
        }
        bundleMgr_ = bundleMgr;
    }

    return bundleMgr_;
}

std::shared_ptr<Media::PixelMap> BundleGraphicsClientImpl::LoadImageFile(const uint8_t *data, size_t len)
{
    APP_LOGI("begin");
    uint32_t errorCode = 0;
    Media::SourceOptions opts;
    std::unique_ptr<Media::ImageSource> imageSource = Media::ImageSource::CreateImageSource(data, len, opts, errorCode);
    if ((errorCode != 0) || (imageSource == nullptr)) {
        APP_LOGE("create image failed %{public}d", errorCode);
        return nullptr;
    }

    Media::DecodeOptions decodeOpts;
    auto pixelMapPtr = imageSource->CreatePixelMap(decodeOpts, errorCode);
    if (errorCode != 0) {
        APP_LOGE("failed create pixelmap %{public}d", errorCode);
        return nullptr;
    }
    APP_LOGI("end");
    return std::shared_ptr<Media::PixelMap>(std::move(pixelMapPtr));
}

ErrCode BundleGraphicsClientImpl::GetAbilityPixelMapIcon(const std::string &bundleName,
    const std::string &moduleName, const std::string &abilityName, std::shared_ptr<Media::PixelMap> &pixelMap)
{
    APP_LOGI("begin");
    auto iBundleMgr = GetBundleMgr();
    if (iBundleMgr == nullptr) {
        APP_LOGE("can not get iBundleMgr");
        return ERR_APPEXECFWK_SERVICE_NOT_READY;
    }
    std::unique_ptr<uint8_t[]> mediaDataPtr = nullptr;
    size_t len = 0;
    ErrCode ret = iBundleMgr->GetMediaData(bundleName, moduleName, abilityName, mediaDataPtr, len);
    if (ret != ERR_OK) {
        APP_LOGE("get media data failed");
        return ret;
    }
    if (mediaDataPtr == nullptr || len == 0) {
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    auto pixelMapPtr = LoadImageFile(mediaDataPtr.get(), len);
    if (pixelMapPtr == nullptr) {
        APP_LOGE("loadImageFile failed");
        return ERR_BUNDLE_MANAGER_INTERNAL_ERROR;
    }
    pixelMap = std::move(pixelMapPtr);
    return ERR_OK;
}
}  // AppExecFwk
}  // OHOS