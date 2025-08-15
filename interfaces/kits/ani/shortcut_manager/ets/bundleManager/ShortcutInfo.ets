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
    iconId?: long;
    label?: string;
    labelId?: long;
    wants?: Array<ShortcutWant>;
    appIndex: int;
    sourceType: int;
    visible?: boolean;
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
    moduleName?: string | undefined;
    hostAbility?: string | undefined;
    icon?: string | undefined;
    iconId?: long | undefined;
    label?: string | undefined;
    labelId?: long | undefined;
    wants?: Array<ShortcutWant> | undefined;
    appIndex: int;
    sourceType: int;
    public visible?: boolean | undefined;

    constructor() { }
    constructor(id: string,
        bundleName: string,
        appIndex: int,
        sourceType: int,
        moduleName?: string,
        hostAbility?: string,
        icon?: string,
        iconId?: long,
        label?: string,
        labelId?: long,
        wants?: Array<ShortcutWant>,
        visible?: boolean) {
            this.id = id;
            this.bundleName = bundleName;
            this.appIndex = appIndex;
            this.sourceType = sourceType;
            this.moduleName = moduleName;
            this.hostAbility = hostAbility;
            this.icon = icon;
            this.iconId = iconId;
            this.label = label;
            this.labelId = labelId;
            this.wants = wants;
            this.visible = visible;
    }
}

class ShortcutWantInner implements ShortcutWant {
    targetBundle: string = "";
    targetModule?: string | undefined;
    targetAbility: string = "";
    parameters?: Array<ParameterItem> | undefined;

    constructor() { }
    constructor(targetBundle: string,
        targetAbility: string,
        targetModule?: string,
        parameters?: Array<ParameterItem>) {
            this.targetBundle = targetBundle;
            this.targetAbility = targetAbility;
            this.targetModule = targetModule;
            this.parameters = parameters;
    }
}

class ParameterItemInner implements ParameterItem {
    key: string = "";
    value: string = "";
    constructor() { }
    constructor(key: string, value: string) {
        this.key = key;
        this.value = value;
    }
}
