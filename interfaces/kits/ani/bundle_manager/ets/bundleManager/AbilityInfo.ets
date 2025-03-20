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

import { ApplicationInfo } from 'bundleManager.ApplicationInfo';
import { Metadata } from 'bundleManager.Metadata';
import { Skill } from 'bundleManager.Skill';
import bundleManager from '@ohos.bundle.bundleManager';

export interface AbilityInfo {
  readonly bundleName: string;
  readonly moduleName: string;
  readonly name: string;
  readonly label: string;
  readonly labelId: number;
  readonly description: string;
  readonly descriptionId: number;
  readonly icon: string;
  readonly iconId: number;
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
  readonly appIndex: number;
  readonly orientationId: number;
}

export interface WindowSize {
  readonly maxWindowRatio: number;
  readonly minWindowRatio: number;
  readonly maxWindowWidth: number;
  readonly minWindowWidth: number;
  readonly maxWindowHeight: number;
  readonly minWindowHeight: number;
}
