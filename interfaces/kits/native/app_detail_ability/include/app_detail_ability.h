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
#ifndef BUNDLE_FRAMEWORK_INTERFACE_KITS_NATIVE_APP_DETAIL_ABILITY_H
#define BUNDLE_FRAMEWORK_INTERFACE_KITS_NATIVE_APP_DETAIL_ABILITY_H

#include "ability.h"
#include <string>

namespace OHOS {
namespace AppExecFwk {
class AppDetailAbility : public Ability {
public:
    void OnStart(const Want &want) override;
};
}  // namespace AppExecFwk
}  // namespace OHOS
#endif  // BUNDLE_FRAMEWORK_INTERFACE_KITS_NATIVE_APP_DETAIL_ABILITY_H