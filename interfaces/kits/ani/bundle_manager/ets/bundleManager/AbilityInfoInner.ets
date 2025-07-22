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
import { AbilityInfo, WindowSize } from 'bundleManager.AbilityInfo';
import { ApplicationInfoInner } from './ApplicationInfoInner';

export class AbilityInfoInner implements AbilityInfo {
  readonly bundleName: string = "";
  readonly moduleName: string = "";
  readonly name: string = "";
  readonly label: string = "";
  readonly labelId: long;
  readonly description: string = "";
  readonly descriptionId: long;
  readonly icon: string = "";
  readonly iconId: long;
  readonly process: string = "";
  readonly exported: boolean;
  readonly orientation: bundleManager.DisplayOrientation = bundleManager.DisplayOrientation.UNSPECIFIED;
  readonly launchType: bundleManager.LaunchType = bundleManager.LaunchType.SINGLETON;
  readonly permissions: Array<string> = new Array<string>;
  readonly deviceTypes: Array<string> = new Array<string>;
  readonly applicationInfo: ApplicationInfo = new ApplicationInfoInner;
  readonly metadata: Array<Metadata> = new Array<Metadata>;
  readonly enabled: boolean;
  readonly supportWindowModes: Array<bundleManager.SupportWindowMode> = new Array<bundleManager.SupportWindowMode>;
  readonly windowSize: WindowSize = new WindowSizeInner;
  readonly excludeFromDock: boolean;
  readonly skills: Array<Skill> = new Array<Skill>;
  readonly appIndex: int;
  readonly orientationId: long;

  constructor() { }
  constructor(bundleName: string,
    moduleName: string,
    name: string,
    label: string,
    labelId: long,
    description: string,
    descriptionId: long,
    icon: string,
    iconId: long,
    process: string,
    exported: boolean,
    orientation: bundleManager.DisplayOrientation,
    launchType: bundleManager.LaunchType,
    permissions: Array<string>,
    deviceTypes: Array<string>,
    applicationInfo: ApplicationInfo,
    metadata: Array<Metadata>,
    enabled: boolean,
    supportWindowModes: Array<bundleManager.SupportWindowMode>,
    windowSize: WindowSize,
    excludeFromDock: boolean,
    skills: Array<Skill>,
    appIndex: int,
    orientationId: long) {
      this.bundleName = bundleName;
      this.moduleName = moduleName;
      this.name = name;
      this.label = label;
      this.labelId = labelId;
      this.description = description;
      this.descriptionId = descriptionId;
      this.icon = icon;
      this.iconId = iconId;
      this.process = process;
      this.exported = exported;
      this.orientation = orientation;
      this.launchType = launchType;
      this.permissions = permissions;
      this.deviceTypes = deviceTypes;
      this.applicationInfo = applicationInfo;
      this.metadata = metadata;
      this.enabled = enabled;
      this.supportWindowModes = supportWindowModes;
      this.windowSize = windowSize;
      this.excludeFromDock = excludeFromDock;
      this.skills = skills;
      this.appIndex = appIndex;
      this.orientationId = orientationId;
  }
}

export class WindowSizeInner implements WindowSize {
  readonly maxWindowRatio: double;
  readonly minWindowRatio: double;
  readonly maxWindowWidth: long;
  readonly minWindowWidth: long;
  readonly maxWindowHeight: long;
  readonly minWindowHeight: long;

  constructor() { }
  constructor(maxWindowRatio: double,
    minWindowRatio: double,
    maxWindowWidth: long,
    minWindowWidth: long,
    maxWindowHeight: long,
    minWindowHeight: long) {
      this.maxWindowRatio = maxWindowRatio;
      this.minWindowRatio = minWindowRatio;
      this.maxWindowWidth = maxWindowWidth;
      this.minWindowWidth = minWindowWidth;
      this.maxWindowHeight = maxWindowHeight;
      this.minWindowHeight = minWindowHeight;
  }
}
