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

#ifndef FOUNDATION_APPEXECFWK_INTERFACES_INNERKITS_APPEXECFWK_BASE_INCLUDE_DISPOSED_RULE_H
#define FOUNDATION_APPEXECFWK_INTERFACES_INNERKITS_APPEXECFWK_BASE_INCLUDE_DISPOSED_RULE_H

#include <string>
#include <vector>

#include "element_name.h"
#include "parcel.h"
#include "want.h"

namespace OHOS {
namespace AppExecFwk {
enum class ComponentType {
    UI_ABILITY = 1,
    UI_EXTENSION = 2,
};

enum class UninstallComponentType {
    EXTENSION = 1,
};

enum class DisposedType {
    BLOCK_APPLICATION = 1,
    BLOCK_ABILITY = 2,
    NON_BLOCK = 3,
};

enum class ControlType {
    ALLOWED_LIST = 1,
    DISALLOWED_LIST = 2,
};

struct DisposedRule : public Parcelable {
public:
    std::shared_ptr<AAFwk::Want> want = nullptr;
    ComponentType componentType = ComponentType::UI_ABILITY;
    DisposedType disposedType = DisposedType::BLOCK_APPLICATION;
    ControlType controlType = ControlType::ALLOWED_LIST;
    std::vector<ElementName> elementList;
    int32_t priority = 0;
    bool isEdm = false;

    // used for log
    std::string callerName;
    int64_t setTime = 0;

    bool ReadFromParcel(Parcel &parcel);
    virtual bool Marshalling(Parcel &parcel) const override;
    static DisposedRule *Unmarshalling(Parcel &parcel);

    static bool FromString(const std::string &ruleString, DisposedRule &rule);
    std::string ToString() const;
};

struct UninstallDisposedRule : public Parcelable {
public:
    std::shared_ptr<AAFwk::Want> want = nullptr;
    UninstallComponentType uninstallComponentType = UninstallComponentType::EXTENSION;
    int32_t priority = 0;

    bool ReadFromParcel(Parcel &parcel);
    virtual bool Marshalling(Parcel &parcel) const override;
    static UninstallDisposedRule *Unmarshalling(Parcel &parcel);

    static bool FromString(const std::string &ruleString, UninstallDisposedRule &rule);
    std::string ToString() const;
};
}  // namespace AppExecFwk
}  // namespace OHOS
#endif  // FOUNDATION_APPEXECFWK_INTERFACES_INNERKITS_APPEXECFWK_BASE_INCLUDE_DISPOSED_RULE_H
