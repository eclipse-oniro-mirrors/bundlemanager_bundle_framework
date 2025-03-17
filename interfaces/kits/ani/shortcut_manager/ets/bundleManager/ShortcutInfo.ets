/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

export interface ShortcutInfo {
    id: string;
    bundleName: string;
    moduleName?: string;
    hostAbility?: string;
    icon?: string;
    iconId?: number;
    label?: string;
    labelId?: number;
    wants?: Array<ShortcutWant>;
    appIndex: number;
    sourceType: number;
}

export interface ShortcutWant {
    targetBundle: string;
    targetModule?: string;
    targetAbility: string;
    parameters?: Array<ParameterItem>;
}

export interface ParameterItem {
    key: string;
    value: string;
}

export class ShortcutInfoInner implements ShortcutInfo {
    id: string = "";
    bundleName: string = "";
    moduleName?: string | undefined = "";
    hostAbility?: string | undefined = "";
    icon?: string | undefined = "";
    iconId?: number | undefined;
    label?: string | undefined = "";
    labelId?: number | undefined;
    wants?: Array<ShortcutWant> | undefined = new Array<ShortcutWant>;
    appIndex: number;
    sourceType: number;
}

class ShortcutWantInner implements ShortcutWant {
    targetBundle: string = "";
    targetModule?: string | undefined = "";
    targetAbility: string = "";
    parameters?: Array<ParameterItem> | undefined = new Array<ParameterItem>;
}

class ParameterItemInner implements ParameterItem {
    key: string = "";
    value: string = "";
}
