/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

import { SkillInfo, SkillType } from 'skillManager.SkillInfo'

export class SkillInfoInner implements SkillInfo {
    readonly bundleName: string = '';
    readonly moduleName: string = '';
    readonly skillName: string = '';
    readonly skillId: int;
    readonly skillType: SkillType;
    readonly hapPath: string = '';
    readonly skillPath: string = '';
    readonly abilityName: string = '';
    readonly description: string = '';
    readonly srcEntries: Array<string> = new Array<string>;
    readonly permissions: Array<string> = new Array<string>;
    readonly requestPermissions: Array<string> = new Array<string>;

    constructor() { }
    constructor(bundleName: string, moduleName: string, skillName: string, skillId: int, skillType: SkillType,
        hapPath: string, skillPath: string, abilityName: string, description: string,
        srcEntries: Array<string>, permissions: Array<string>, requestPermissions: Array<string>) {
        this.bundleName = bundleName;
        this.moduleName = moduleName;
        this.skillName = skillName;
        this.skillId = skillId;
        this.skillType = skillType;
        this.hapPath = hapPath;
        this.skillPath = skillPath;
        this.abilityName = abilityName;
        this.description = description;
        this.srcEntries = srcEntries;
        this.permissions = permissions;
        this.requestPermissions = requestPermissions;
    }
}
