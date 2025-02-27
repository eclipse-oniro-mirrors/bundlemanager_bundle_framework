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

import { AbilityInfo } from './AbilityInfo';
import { ExtensionAbilityInfo } from './ExtensionAbilityInfo';
import { Metadata } from './Metadata';
import bundleManager from './@ohos.bundle.bundleManager';

export interface HapModuleInfo {
  readonly name: string;
  readonly icon: string;
  readonly iconId: int;
  readonly label: string;
  readonly labelId: int;
  readonly description: string;
  readonly descriptionId: int;
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
  readonly versionCode: int;
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

class HapModuleInfoInner implements HapModuleInfo {
  readonly name: string = "";
  readonly icon: string = "";
  readonly iconId: int;
  readonly label: string = "";
  readonly labelId: int;
  readonly description: string = "";
  readonly descriptionId: int;
  readonly mainElementName: string = "";
  readonly abilitiesInfo: Array<AbilityInfo> = new Array<AbilityInfo>;
  readonly extensionAbilitiesInfo: Array<ExtensionAbilityInfo> = new Array<ExtensionAbilityInfo>;
  readonly metadata: Array<Metadata> = new Array<Metadata>;
  readonly deviceTypes: Array<string> = new Array<string>;
  readonly installationFree: boolean;
  readonly hashValue: string = "";
  readonly type: bundleManager.ModuleType;
  readonly dependencies: Array<Dependency> = new Array<Dependency>;
  readonly preloads: Array<PreloadItem> = new Array<PreloadItem>;
  readonly fileContextMenuConfig: string = "";
  readonly routerMap: Array<RouterItem> = new Array<RouterItem>;
  readonly nativeLibraryPath: string = "";
  readonly codePath: string = "";
}

class DependencyInner implements Dependency {
  readonly moduleName: string = "";
  readonly bundleName: string = "";
  readonly versionCode: int;
}

class PreloadItemInner implements PreloadItem {
  readonly moduleName: string = "";
}

class RouterItemInner implements RouterItem {
  readonly name: string = "";
  readonly pageSourceFile: string = "";
  readonly buildFunction: string = "";
  readonly customData: string = "";
  readonly data: Array<DataItem> = new Array<DataItem>;
}

class DataItemInner implements DataItem {
  readonly key: string = "";
  readonly value: string = "";
}
