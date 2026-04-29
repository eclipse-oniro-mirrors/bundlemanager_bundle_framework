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

import { SkillInfo } from 'skillManager.SkillInfo'
import { SkillInfoInner } from './skillManager/SkillInfoInner'

namespace skillManager {
  export enum SkillInfoFlag {
    GET_SKILL_INFO_DEFAULT = 0x00000000,
    GET_SKILL_INFO_WITH_DESCRIPTION = 0x00000001,
    GET_SKILL_INFO_WITH_SRC_ENTRIES = 0x00000002,
    GET_SKILL_INFO_WITH_PERMISSIONS = 0x00000004,
    GET_SKILL_INFO_WITH_REQUEST_PERMISSIONS = 0x00000008,
  }

  export type SkillInfo = SkillInfo;

  native function getSkillInfoForSelfNative(moduleName: string, skillName: string,
    flags: int, userId: int): SkillInfo;

  native function getSkillInfosForSelfNative(flags: int, userId: int): Array<SkillInfo>;

  native function getSkillInfoNative(bundleName: string, moduleName: string,
    skillName: string, flags: int, userId: int): SkillInfo;

  native function getSkillInfosNative(bundleName: string, flags: int, userId: int): Array<SkillInfo>;

  native function getAllSkillInfosNative(flags: int, userId: int): Array<SkillInfo>;

  function getSkillInfoForSelf(moduleName: string, skillName: string,
    flags: int, userId?: int): Promise<SkillInfo> {
    let defaultUserId = userId === undefined ? 0 : userId;
    return new Promise((resolve, reject) => {
      try {
        let result = getSkillInfoForSelfNative(moduleName, skillName, flags, defaultUserId);
        resolve(result);
      } catch (err) {
        reject(err);
      }
    });
  }

  function getSkillInfosForSelf(flags: int, userId?: int): Promise<Array<SkillInfo>> {
    let defaultUserId = userId === undefined ? 0 : userId;
    return new Promise((resolve, reject) => {
      try {
        let result = getSkillInfosForSelfNative(flags, defaultUserId);
        resolve(result);
      } catch (err) {
        reject(err);
      }
    });
  }

  function getSkillInfo(bundleName: string, moduleName: string, skillName: string,
    flags: int, userId?: int): Promise<SkillInfo> {
    let defaultUserId = userId === undefined ? 0 : userId;
    return new Promise((resolve, reject) => {
      try {
        let result = getSkillInfoNative(bundleName, moduleName, skillName, flags, defaultUserId);
        resolve(result);
      } catch (err) {
        reject(err);
      }
    });
  }

  function getSkillInfos(bundleName: string, flags: int, userId?: int): Promise<Array<SkillInfo>> {
    let defaultUserId = userId === undefined ? 0 : userId;
    return new Promise((resolve, reject) => {
      try {
        let result = getSkillInfosNative(bundleName, flags, defaultUserId);
        resolve(result);
      } catch (err) {
        reject(err);
      }
    });
  }

  function getAllSkillInfos(flags: int, userId?: int): Promise<Array<SkillInfo>> {
    let defaultUserId = userId === undefined ? 0 : userId;
    return new Promise((resolve, reject) => {
      try {
        let result = getAllSkillInfosNative(flags, defaultUserId);
        resolve(result);
      } catch (err) {
        reject(err);
      }
    });
  }
}
