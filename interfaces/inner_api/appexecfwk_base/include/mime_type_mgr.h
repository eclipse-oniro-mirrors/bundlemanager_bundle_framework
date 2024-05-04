/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#ifndef FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_MIME_TYPE_MGR_H
#define FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_MIME_TYPE_MGR_H

#include <map>
#include <string>
#include <vector>

namespace OHOS {
namespace AppExecFwk {
class MimeTypeMgr {
public:
    MimeTypeMgr() = default;
    ~MimeTypeMgr() = default;
    static bool GetMimeTypeByUri(const std::string &uri, std::vector<std::string> &mimeTypes);
    static bool GetMimeTypeByUri(const std::string &uri, std::string &mimeType);
    static bool GetUriSuffix(const std::string &uri, std::string &suffix);

private:
    static std::multimap<std::string, std::string> mimeTypeMap_;
};
}
}
#endif