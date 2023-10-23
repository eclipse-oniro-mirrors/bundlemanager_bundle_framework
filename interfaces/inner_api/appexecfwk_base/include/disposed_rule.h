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

struct DisposedRule : public Parcelable {
public:
    AAFwk::Want want;
    int32_t componentType;
    int32_t disposedType;
    int32_t controlType;
    std::vector<ElementName> elementsList;
    int32_t priority;

    bool ReadFromParcel(Parcel &parcel);
    virtual bool Marshalling(Parcel &parcel) const override;
    static DisposedRule *Unmarshalling(Parcel &parcel);

    static bool FromString(const std::string &ruleString, DisposedRule &rule);
    std::string ToString() const;
};
}  // namespace AppExecFwk
}  // namespace OHOS
#endif  // FOUNDATION_APPEXECFWK_INTERFACES_INNERKITS_APPEXECFWK_BASE_INCLUDE_DISPOSED_RULE_H
