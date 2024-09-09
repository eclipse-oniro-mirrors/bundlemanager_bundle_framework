/*
 * Copyright (c) 2023-2024 Huawei Device Co., Ltd.
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

#include "mime_type_mgr.h"

#include <memory>

#include "app_log_wrapper.h"
#include "bundle_constants.h"
#ifdef BUNDLE_FRAMEWORK_UDMF_ENABLED
#include "type_descriptor.h"
#include "utd_client.h"
#endif

namespace OHOS {
namespace AppExecFwk {
namespace {
const char* ZIP_FORMAT = ".zip.";
const char* ZIP_SUFFIX = ".zip";
const char* FILE_7Z_FORMAT = ".7z.";
const char* FILE_7Z_SUFFIX = ".7z";
}

bool MimeTypeMgr::GetMimeTypeByUri(const std::string &uri, std::vector<std::string> &mimeTypes)
{
#ifdef BUNDLE_FRAMEWORK_UDMF_ENABLED
    std::vector<std::string> utdVector;
    if (!GetUtdVectorByUri(uri, utdVector)) {
        APP_LOGD("Get utd vector by uri %{private}s failed", uri.c_str());
        return false;
    }
    for (const std::string &utd : utdVector) {
        std::shared_ptr<UDMF::TypeDescriptor> typeDescriptor;
        auto ret = UDMF::UtdClient::GetInstance().GetTypeDescriptor(utd, typeDescriptor);
        if (ret != ERR_OK || typeDescriptor == nullptr) {
            APP_LOGE("GetTypeDescriptor failed");
            continue;
        }
        std::vector<std::string> tmpMimeTypes = typeDescriptor->GetMimeTypes();
        if (tmpMimeTypes.empty()) {
            APP_LOGD("tmpMimeTypes empty");
            continue;
        }
        mimeTypes.insert(mimeTypes.end(), tmpMimeTypes.begin(), tmpMimeTypes.end());
    }
    return !mimeTypes.empty();
#else
    return false;
#endif
}

bool MimeTypeMgr::GetMimeTypeByUri(const std::string &uri, std::string &mimeType)
{
    std::vector<std::string> mimeTypes;
    bool ret = GetMimeTypeByUri(uri, mimeTypes);
    if (!ret) {
        return false;
    }
    mimeType = mimeTypes[0];
    return true;
}

bool MimeTypeMgr::GetUriSuffix(const std::string &uri, std::string &suffix)
{
    if (uri.find(ZIP_FORMAT) != std::string::npos) {
        suffix = ZIP_SUFFIX;
        return true;
    }
    if (uri.find(FILE_7Z_FORMAT) != std::string::npos) {
        suffix = FILE_7Z_SUFFIX;
        return true;
    }
    auto suffixIndex = uri.rfind('.');
    if (suffixIndex == std::string::npos) {
        APP_LOGD("Get suffix failed %{private}s", uri.c_str());
        return false;
    }
    suffix = uri.substr(suffixIndex);
    std::transform(suffix.begin(), suffix.end(), suffix.begin(),
                [](unsigned char c) { return std::tolower(c); });
    return true;
}

bool MimeTypeMgr::GetUtdVectorByUri(const std::string &uri, std::vector<std::string> &utdVector)
{
#ifdef BUNDLE_FRAMEWORK_UDMF_ENABLED
    std::string suffix;
    if (!GetUriSuffix(uri, suffix)) {
        APP_LOGD("Get suffix failed %{private}s", uri.c_str());
        return false;
    }
    auto ret = UDMF::UtdClient::GetInstance().GetUniformDataTypesByFilenameExtension(suffix, utdVector);
    if (ret != ERR_OK || utdVector.empty()) {
        APP_LOGD("Get utd vector by suffix %{public}s failed. err %{public}d", suffix.c_str(), ret);
        return false;
    }
    return true;
#else
    return false;
#endif
}
}
}