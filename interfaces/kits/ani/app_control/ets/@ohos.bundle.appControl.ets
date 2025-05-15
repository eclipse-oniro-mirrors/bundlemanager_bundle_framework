/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/**
 * @file
 * @kit AbilityKit
 */

import { AsyncCallback, BusinessError } from '@ohos.base';
import { ElementName } from 'bundleManager.ElementName';
import Want from '@ohos.app.ability.Want';

export default namespace appControl {
  loadLibrary("ani_app_control.z");

  export enum ComponentType {
    UI_ABILITY = 1,
    UI_EXTENSION = 2
  }

  export enum UninstallComponentType {
    EXTENSION = 1,
  }

  export enum DisposedType {
    BLOCK_APPLICATION = 1,
    BLOCK_ABILITY = 2,
    NON_BLOCK = 3
  }

  export enum ControlType {
    ALLOWED_LIST = 1,
    DISALLOWED_LIST = 2
  }

  export interface DisposedRule {
    want: Want;
    componentType: ComponentType;
    disposedType: DisposedType;
    controlType: ControlType;
    elementList: Array<ElementName>;
    priority: number;
  }

  export interface UninstallDisposedRule {
    want: Want;
    uninstallComponentType: UninstallComponentType;
    priority: number;
  }

  export class DisposedRuleInner implements DisposedRule {
    public want: Want = {};
    public componentType: ComponentType = ComponentType.UI_ABILITY;
    public disposedType: DisposedType = DisposedType.BLOCK_APPLICATION;
    public controlType: ControlType = ControlType.ALLOWED_LIST;
    public elementList: Array<ElementName>;
    public priority: number;
  }

  export class UninstallDisposedRuleInner implements UninstallDisposedRule {
    public want: Want = {};
    public uninstallComponentType: UninstallComponentType = UninstallComponentType.EXTENSION;
    public priority: number;
  }

  export native function setDisposedStatusSync(appId: string, disposedWant: Want): void;
  export native function getDisposedStatusSync(appId: string): Want;
  export native function deleteDisposedStatusSyncNative(appId: string, appIndex: number): void;
  export native function getDisposedRuleNative(appId: string, appIndex: number): DisposedRule;
  export native function setDisposedRuleNative(appId: string, rule: DisposedRule, appIndex: number): void;
  export native function setUninstallDisposedRuleNative(appIdentifier: string, rule: UninstallDisposedRule, appIndex: number): void;
  export native function getUninstallDisposedRuleNative(appIdentifier: string, appIndex: number): UninstallDisposedRule;
  export native function deleteUninstallDisposedRuleNative(appIdentifier: string, appIndex: number): void;


  function setDisposedStatus(appId: string, disposedWant: Want, callback: AsyncCallback<void>): void {
    let cb = (): void => {
      return appControl.setDisposedStatusSync(appId, disposedWant);
    };
    let p1 = taskpool.execute(cb);
    p1.then(() => {
      let br: BusinessError = new BusinessError();
      callback(br, undefined);
    }, (err: BusinessError): void => {
      callback(err, undefined);
    });
  }

  function setDisposedStatus(appId: string, disposedWant: Want): Promise<void> {
    let p = new Promise<void>((resolve: (v: undefined) => void, reject: (error: BusinessError) => void) : void => {
      let cb = (): void => {
        return appControl.setDisposedStatusSync(appId, disposedWant);
      };
      let p1 = taskpool.execute(cb);
      p1.then((): void => {
        resolve(undefined);
      }, (err: BusinessError): void => {
        reject(err);
      });
    }
    );
    return p;
  }

  function getDisposedStatus(appId: string, callback: AsyncCallback<Want>): void {
    let cb = (): Want => {
      return appControl.getDisposedStatusSync(appId);
    };
    let p1 = taskpool.execute(cb);
    p1.then((e: NullishType) => {
      let result: Want = e as Want;
      let br: BusinessError = new BusinessError();
      callback(br, result);
    }, (err: BusinessError): void => {
      let result: Want = {};
      callback(err, result);
    });
  }

  function getDisposedStatus(appId: string): Promise<Want> {
    let p = new Promise<Want>((resolve: (want: Want) => void, reject: (error: BusinessError) => void) => {
      let cb = (): Want => {
        return appControl.getDisposedStatusSync(appId);
      };
      let p1 = taskpool.execute(cb);
      p1.then((e: NullishType) => {
        let result: Want = e as Want;
        resolve(result);
      }, (err: BusinessError): void => {
        reject(err);
      });
    });
    return p;
  }

  function deleteDisposedStatus(appId: string, callback: AsyncCallback<void>): void {
    let cb = (): void => {
      return appControl.deleteDisposedStatusSyncNative(appId, 0);
    };
    let p1 = taskpool.execute(cb);
    p1.then(() => {
      let br: BusinessError = new BusinessError();
      callback(br, undefined);
    }, (err: BusinessError): void => {
      callback(err, undefined);
    });
  }

  function deleteDisposedStatus(appId: string): Promise<void> {
    let p = new Promise<void>((resolve: (v: undefined) => void, reject: (error: BusinessError) => void) : void => {
      let cb = (): void => {
        return appControl.deleteDisposedStatusSyncNative(appId, 0);
      };
      let p1 = taskpool.execute(cb);
      p1.then((): void => {
        resolve(undefined);
      }, (err: BusinessError): void => {
        reject(err);
      });
    }
    );
    return p;
  }

  function deleteDisposedStatusSync(appId: string, appIndex?: number): void
  {
    let appIndexInfo = appIndex ?? 0;
    appControl.deleteDisposedStatusSyncNative(appId, appIndexInfo);
  }

  function getDisposedRule(appId: string, appIndex?: number): DisposedRule
  {
    let appIndexInfo = appIndex ?? 0;
    return appControl.getDisposedRuleNative(appId, appIndexInfo);
  }

  function setDisposedRule(appId: string, rule: DisposedRule, appIndex?: number): void
  {
    let appIndexInfo = appIndex ?? 0;
    appControl.setDisposedRuleNative(appId, rule, appIndexInfo);
  }

  function setUninstallDisposedRule(appIdentifier: string, rule: UninstallDisposedRule, appIndex?: number): void
  {
    let appIndexInfo = appIndex ?? 0;
    appControl.setUninstallDisposedRuleNative(appIdentifier, rule, appIndexInfo);
  }

  function getUninstallDisposedRule(appIdentifier: string, appIndex?: number): UninstallDisposedRule
  {
    let appIndexInfo = appIndex ?? 0;
    return appControl.getUninstallDisposedRuleNative(appIdentifier, appIndexInfo);
  }

  function deleteUninstallDisposedRule(appIdentifier: string, appIndex?: number): void
  {
    let appIndexInfo = appIndex ?? 0;
    appControl.deleteUninstallDisposedRuleNative(appIdentifier, appIndexInfo);
  }
}