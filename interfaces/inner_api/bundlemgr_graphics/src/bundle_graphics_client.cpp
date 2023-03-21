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

#include "bundle_graphics_client.h"

#include "app_log_wrapper.h"
#include "bundle_graphics_client_impl.h"

namespace OHOS {
namespace AppExecFwk {
BundleGraphicsClient::BundleGraphicsClient()
{
    impl_ = BundleGraphicsClientImpl::GetInstance();
}

ErrCode BundleGraphicsClient::GetAbilityPixelMapIcon(const std::string &bundleName,
    const std::string &moduleName, const std::string &abilityName, std::shared_ptr<Media::PixelMap> &pixelMapPtr)
{
    if (impl_ == nullptr) {
        APP_LOGE("bundlemgr graphics client impl is nullptr");
        return ERR_BUNDLE_MANAGER_INTERNAL_ERROR;
    }
    return impl_->GetAbilityPixelMapIcon(bundleName, moduleName, abilityName, pixelMapPtr);
}
}  // AppExecFwk
}  // OHOS