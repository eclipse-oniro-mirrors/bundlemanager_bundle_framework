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

import { SkillInfo, SkillType } from 'bundleManager.SkillInfo'

export class SkillInfoInner implements SkillInfo {
    public readonly bundleName: string = '';
    public readonly moduleName: string = '';
    public readonly skillName: string = '';
    public readonly skillType: SkillType = SkillType.APP_SKILL;
    public readonly skillPath: string = '';
    public readonly abilityName: string = '';
    public readonly versionCode: long;
    public readonly version?: string;
    public readonly visibility?: string;
    public readonly description?: string;
    public readonly srcEntries?: Array<string>;
    public readonly permissions?: Array<string>;
    public readonly requestPermissions?: Array<string>;

    constructor() { }
    constructor(bundleName: string, moduleName: string, skillName: string, skillType: SkillType,
        skillPath: string, abilityName: string, versionCode: long, version?: string,
        visibility?: string, description?: string,
        srcEntries?: Array<string>, permissions?: Array<string>,
        requestPermissions?: Array<string>) {
        this.bundleName = bundleName;
        this.moduleName = moduleName;
        this.skillName = skillName;
        this.skillType = skillType;
        this.skillPath = skillPath;
        this.abilityName = abilityName;
        this.versionCode = versionCode;
        this.version = version;
        this.visibility = visibility;
        this.description = description;
        this.srcEntries = srcEntries;
        this.permissions = permissions;
        this.requestPermissions = requestPermissions;
    }
}
