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

import { AbilityInfo } from 'bundleManager.AbilityInfo';
import { ExtensionAbilityInfo } from 'bundleManager.ExtensionAbilityInfo';
import { Metadata } from 'bundleManager.Metadata';
import bundleManager from '@ohos.bundle.bundleManager';

export interface HapModuleInfo {
  readonly name: string;
  readonly icon: string;
  readonly iconId: number;
  readonly label: string;
  readonly labelId: number;
  readonly description: string;
  readonly descriptionId: number;
  readonly mainElementName: string;
  readonly abilitiesInfo: Array<AbilityInfo>;
  readonly extensionAbilitiesInfo: Array<ExtensionAbilityInfo>;
  readonly metadata: Array<Metadata>;
  readonly deviceTypes: Array<string>;
  readonly installationFree: boolean;
  readonly hashValue: string;
  readonly type: bundleManager.ModuleType;
  readonly dependencies: Array<Dependency>;
  readonly preloads: Array<PreloadItem>;
  readonly fileContextMenuConfig: string;
  readonly routerMap: Array<RouterItem>;
  readonly nativeLibraryPath: string;
  readonly codePath: string;
}

export interface Dependency {
  readonly moduleName: string;
  readonly bundleName: string;
  readonly versionCode: number;
}

export interface PreloadItem {
  readonly moduleName: string;
}

export interface RouterItem {
  readonly name: string;
  readonly pageSourceFile: string;
  readonly buildFunction: string;
  readonly customData: string;
  readonly data: Array<DataItem>;
}

export interface DataItem {
  readonly key: string;
  readonly value: string;
}