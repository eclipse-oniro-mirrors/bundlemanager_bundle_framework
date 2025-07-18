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
  readonly labelId: long;
  readonly description: string;
  readonly descriptionId: long;
  readonly icon: string;
  readonly iconId: long;
  readonly process: string;
  readonly exported: boolean;
  readonly orientation: bundleManager.DisplayOrientation;
  readonly launchType: bundleManager.LaunchType;
  readonly permissions: Array<string>;
  readonly deviceTypes: Array<string>;
  readonly applicationInfo: ApplicationInfo | null;
  readonly metadata: Array<Metadata>;
  readonly enabled: boolean;
  readonly supportWindowModes: Array<bundleManager.SupportWindowMode>;
  readonly windowSize: WindowSize;
  readonly excludeFromDock: boolean;
  readonly skills: Array<Skill>;
  readonly appIndex: int;
  readonly orientationId: long;
}

export interface WindowSize {
  readonly maxWindowRatio: double;
  readonly minWindowRatio: double;
  readonly maxWindowWidth: long;
  readonly minWindowWidth: long;
  readonly maxWindowHeight: long;
  readonly minWindowHeight: long;
}
