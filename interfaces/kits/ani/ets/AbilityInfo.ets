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

import { ResourceInner } from './resource';
import { ApplicationInfoInner } from './ApplicationInfo';

export interface AbilityInfo {
  readonly bundleName: string;
  readonly moduleName: string;
  readonly name: string;
  readonly label: string;
  readonly labelId: int;
  readonly description: string;
  readonly descriptionId: int;
  readonly icon: string;
  readonly iconId: int;
  readonly process: string;
  readonly exported: boolean;
  readonly type: bundleManager.AbilityType;
  readonly orientation: bundleManager.DisplayOrientation;
  readonly launchType: bundleManager.LaunchType;
  readonly permissions: Array<string>;
  readonly readPermission: string;
  readonly writePermission: string;
  readonly uri: string;
  readonly deviceTypes: Array<string>;
  readonly applicationInfo: ApplicationInfo;
  readonly metadata: Array<Metadata>;
  readonly enabled: boolean;
  readonly supportWindowModes: Array<bundleManager.SupportWindowMode>;
  readonly windowSize: WindowSize;
  readonly excludeFromDock: boolean;
  readonly skills: Array<Skill>;
  readonly appIndex: int;
  readonly orientationId: int;
}

export interface WindowSize {
  readonly maxWindowRatio: int;
  readonly minWindowRatio: int;
  readonly maxWindowWidth: int;
  readonly minWindowWidth: int;
  readonly maxWindowHeight: int;
  readonly minWindowHeight: int;
}

class AbilityInfoInner implements AbilityInfo {
  readonly bundleName: string = "";
  readonly moduleName: string = "";
  readonly name: string = "";
  readonly label: string = "";
  readonly labelId: int;
  readonly description: string = "";
  readonly descriptionId: int;
  readonly icon: string = "";
  readonly iconId: int;
  readonly process: string = "";
  readonly exported: boolean;
  readonly type: bundleManager.AbilityType;
  readonly orientation: bundleManager.DisplayOrientation;
  readonly launchType: bundleManager.LaunchType;
  readonly permissions: Array<string> = new Array<string>;
  readonly readPermission: string = "";
  readonly writePermission: string = "";
  readonly uri: string = "";
  readonly deviceTypes: Array<string> = new Array<string>;
  readonly applicationInfo: ApplicationInfo = new ApplicationInfoInner;
  readonly metadata: Array<Metadata> = new Array<Metadata>;
  readonly enabled: boolean;
  readonly supportWindowModes: Array<bundleManager.SupportWindowMode> = new Array<bundleManager.SupportWindowMode>;
  readonly windowSize: WindowSize = new WindowSizeInner;
  readonly excludeFromDock: boolean;
  readonly skills: Array<Skill> = new Array<Skill>;
  readonly appIndex: int;
  readonly orientationId: int;
}

class WindowSizeInner implements WindowSize {
  readonly maxWindowRatio: int;
  readonly minWindowRatio: int;
  readonly maxWindowWidth: int;
  readonly minWindowWidth: int;
  readonly maxWindowHeight: int;
  readonly minWindowHeight: int;
}
