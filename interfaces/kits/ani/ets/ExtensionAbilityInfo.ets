/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

import { ApplicationInfo } from './ApplicationInfo';
import { Metadata } from './Metadata';
import bundleManager from './@ohos.bundle.bundleManager';
import { Skill } from './Skill';

import { ApplicationInfoInner } from './ApplicationInfo';

export interface ExtensionAbilityInfo {
  readonly bundleName: string;
  readonly moduleName: string;
  readonly name: string;
  readonly labelId: number;
  readonly descriptionId: number;
  readonly iconId: number;
  readonly exported: boolean;
  readonly extensionAbilityType: bundleManager.ExtensionAbilityType;
  readonly extensionAbilityTypeName: string;
  readonly permissions: Array<string>;
  readonly applicationInfo: ApplicationInfo;
  readonly metadata: Array<Metadata>;
  readonly enabled: boolean;
  readonly readPermission: string;
  readonly writePermission: string;
  readonly skills: Array<Skill>;
  readonly appIndex: number;
}

class ExtensionAbilityInfoInner implements ExtensionAbilityInfo {
  readonly bundleName: string = "";
  readonly moduleName: string = "";
  readonly name: string = "";
  readonly labelId: number;
  readonly descriptionId: number;
  readonly iconId: number;
  readonly exported: boolean;
  readonly extensionAbilityType: bundleManager.ExtensionAbilityType = bundleManager.ExtensionAbilityType.UNSPECIFIED;
  readonly extensionAbilityTypeName: string = "";
  readonly permissions: Array<string> = new Array<string>;
  readonly applicationInfo: ApplicationInfo = new ApplicationInfoInner;
  readonly metadata: Array<Metadata> = new Array<Metadata>;
  readonly enabled: boolean;
  readonly readPermission: string = "";
  readonly writePermission: string = "";
  readonly skills: Array<Skill> = new Array<Skill>;
  readonly appIndex: number;
}
