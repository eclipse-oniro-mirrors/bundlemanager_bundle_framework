/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#ifndef FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_SHARE_FILE_HELPER_H
#define FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_SHARE_FILE_HELPER_H

#include <string>

namespace OHOS {
namespace AppExecFwk {

class ShareFileHelper {
public:
    /**
     * @brief Set share file information for a bundle.
     * @param cfgInfo Indicates the configuration info of share files in JSON format.
     * @param bundleName Indicates the bundle name.
     * @param userId Indicates the user ID.
     * @param tokenId Indicates the access token ID.
     * @return Returns 0 if successful; returns error code otherwise.
     */
    static int32_t SetShareFileInfo(const std::string &cfgInfo, const std::string &bundleName,
        uint32_t userId, uint32_t tokenId);

    /**
     * @brief Update share file information for a bundle.
     * @param cfgInfo Indicates the configuration info of share files in JSON format.
     * @param bundleName Indicates the bundle name.
     * @param userId Indicates the user ID.
     * @param tokenId Indicates the access token ID.
     * @return Returns 0 if successful; returns error code otherwise.
     */
    static int32_t UpdateShareFileInfo(const std::string &cfgInfo, const std::string &bundleName,
        uint32_t userId, uint32_t tokenId);

    /**
     * @brief Unset share file information for a bundle.
     * @param tokenId Indicates the access token ID.
     * @param bundleName Indicates the bundle name.
     * @param userId Indicates the user ID.
     * @return Returns 0 if successful; returns error code otherwise.
     */
    static int32_t UnsetShareFileInfo(uint32_t tokenId, const std::string &bundleName, uint32_t userId);
};

}  // namespace AppExecFwk
}  // namespace OHOS

#endif  // FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_SHARE_FILE_HELPER_H
