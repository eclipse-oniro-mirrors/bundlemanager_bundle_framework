/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

import { SkillInfo as _SkillInfo, SkillType as _SkillType } from 'bundleManager.SkillInfo';
import { BusinessError } from '@ohos.base';

namespace skillManager {
  loadLibraryWithPermissionCheck("ani_skill_manager.z", "@ohos.bundle.skillManager");

  // Keep in sync with EMPTY_USER_ID (-500) in interfaces/kits/js/common/napi_constants.h
  const EMPTY_VALUE: int = -500;

  export enum SkillInfoFlag {
    GET_SKILL_INFO_DEFAULT = 0x00000000,
    GET_SKILL_INFO_WITH_DESCRIPTION = 0x00000001,
    GET_SKILL_INFO_WITH_SRC_ENTRIES = 0x00000002,
    GET_SKILL_INFO_WITH_PERMISSIONS = 0x00000004,
    GET_SKILL_INFO_WITH_REQUEST_PERMISSIONS = 0x00000008,
  }

  native function getSkillInfoForSelfNative(moduleName: string, skillName: string,
    flags: int): SkillInfo;

  native function getSkillInfosForSelfNative(flags: int): Array<SkillInfo>;

  native function getSkillInfoNative(bundleName: string, moduleName: string,
    skillName: string, flags: int, userId: int): SkillInfo;

  native function getSkillInfosNative(bundleName: string, flags: int, userId: int): Array<SkillInfo>;

  native function getAllSkillInfosNative(flags: int, userId: int): Array<SkillInfo>;

  function getSkillInfoForSelf(moduleName: string, skillName: string,
    flags: int): Promise<SkillInfo> {
    let p = new Promise<SkillInfo>((resolve: (skillInfo: SkillInfo) => void,
      reject: (error: BusinessError) => void) => {
      let execFun = (): SkillInfo => {
        return getSkillInfoForSelfNative(moduleName, skillName, flags);
      };
      let p1 = taskpool.execute(execFun);
      p1.then((e: Any) => {
        let result: SkillInfo = e as SkillInfo;
        resolve(result);
      }, (err: Error): void => {
        reject(err as BusinessError);
      });
    });
    return p;
  }

  function getSkillInfosForSelf(flags: int): Promise<Array<SkillInfo>> {
    let p = new Promise<Array<SkillInfo>>((resolve: (skillInfos: Array<SkillInfo>) => void,
      reject: (error: BusinessError) => void) => {
      let execFun = (): Array<SkillInfo> => {
        return getSkillInfosForSelfNative(flags);
      };
      let p1 = taskpool.execute(execFun);
      p1.then((e: Any) => {
        let result: Array<SkillInfo> = e as Array<SkillInfo>;
        resolve(result);
      }, (err: Error): void => {
        reject(err as BusinessError);
      });
    });
    return p;
  }

  function getSkillInfo(bundleName: string, moduleName: string, skillName: string,
    flags: int, userId?: int): Promise<SkillInfo> {
    let userIdInfo: int = userId ?? EMPTY_VALUE;
    let p = new Promise<SkillInfo>((resolve: (skillInfo: SkillInfo) => void,
      reject: (error: BusinessError) => void) => {
      let execFun = (): SkillInfo => {
        return getSkillInfoNative(bundleName, moduleName, skillName, flags, userIdInfo);
      };
      let p1 = taskpool.execute(execFun);
      p1.then((e: Any) => {
        let result: SkillInfo = e as SkillInfo;
        resolve(result);
      }, (err: Error): void => {
        reject(err as BusinessError);
      });
    });
    return p;
  }

  function getSkillInfos(bundleName: string, flags: int, userId?: int): Promise<Array<SkillInfo>> {
    let userIdInfo: int = userId ?? EMPTY_VALUE;
    let p = new Promise<Array<SkillInfo>>((resolve: (skillInfos: Array<SkillInfo>) => void,
      reject: (error: BusinessError) => void) => {
      let execFun = (): Array<SkillInfo> => {
        return getSkillInfosNative(bundleName, flags, userIdInfo);
      };
      let p1 = taskpool.execute(execFun);
      p1.then((e: Any) => {
        let result: Array<SkillInfo> = e as Array<SkillInfo>;
        resolve(result);
      }, (err: Error): void => {
        reject(err as BusinessError);
      });
    });
    return p;
  }

  function getAllSkillInfos(flags: int, userId?: int): Promise<Array<SkillInfo>> {
    let userIdInfo: int = userId ?? EMPTY_VALUE;
    let p = new Promise<Array<SkillInfo>>((resolve: (skillInfos: Array<SkillInfo>) => void,
      reject: (error: BusinessError) => void) => {
      let execFun = (): Array<SkillInfo> => {
        return getAllSkillInfosNative(flags, userIdInfo);
      };
      let p1 = taskpool.execute(execFun);
      p1.then((e: Any) => {
        let result: Array<SkillInfo> = e as Array<SkillInfo>;
        resolve(result);
      }, (err: Error): void => {
        reject(err as BusinessError);
      });
    });
    return p;
  }

  export type SkillInfo = _SkillInfo;

  export type SkillType = _SkillType;
}
