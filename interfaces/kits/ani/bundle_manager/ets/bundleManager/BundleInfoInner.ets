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
import { HapModuleInfo, RouterItem } from 'bundleManager.HapModuleInfo';
import bundleManager from '@ohos.bundle.bundleManager';
import { BundleInfo, ReqPermissionDetail, UsedScene, SignatureInfo, AppCloneIdentity } from 'bundleManager.BundleInfo';
import { ApplicationInfoInner } from './ApplicationInfoInner';

export class BundleInfoInner implements BundleInfo {
  readonly name: string = "";
  readonly vendor: string = "";
  readonly versionCode: number;
  readonly versionName: string = "";
  readonly minCompatibleVersionCode: number;
  readonly targetVersion: number;
  readonly appInfo: ApplicationInfo = new ApplicationInfoInner;
  readonly hapModulesInfo: Array<HapModuleInfo> = new Array<HapModuleInfo>;
  readonly reqPermissionDetails: Array<ReqPermissionDetail> = new Array<ReqPermissionDetail>;
  readonly permissionGrantStates: Array<bundleManager.PermissionGrantState> = new Array<bundleManager.PermissionGrantState>;
  readonly signatureInfo: SignatureInfo = new SignatureInfoInner;
  readonly routerMap: Array<RouterItem> = new Array<RouterItem>;
  readonly installTime: number;
  readonly updateTime: number;
  readonly appIndex: number;
  readonly firstInstallTime?: number;
}

export class ReqPermissionDetailInner implements ReqPermissionDetail {
  name: string = "";
  moduleName: string = "";
  reason: string = "";
  reasonId: number;
  usedScene: UsedScene = new UsedSceneInner;
}

export class UsedSceneInner implements UsedScene {
  abilities: Array<string> = new Array<string>;
  when: string = "";
}

export class SignatureInfoInner implements SignatureInfo {
  readonly appId: string = "";
  readonly fingerprint: string = "";
  readonly appIdentifier: string = "";
  readonly certificate?: string | undefined = "";
}

export class AppCloneIdentityInner implements AppCloneIdentity {
  readonly bundleName: string = "";
  readonly appIndex: number;
}