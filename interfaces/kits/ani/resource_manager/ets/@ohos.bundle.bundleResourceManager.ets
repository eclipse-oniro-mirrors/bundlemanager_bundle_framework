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

import { BundleResourceInfo } from 'bundleManager.BundleResourceInfo';

export default namespace bundleResourceManager {

  loadLibrary("ani_bundle_res_manager.z");

  const INVALID_INT: number = -500;

  enum ResourceFlag {
    GET_RESOURCE_INFO_ALL = 0x00000001,
    GET_RESOURCE_INFO_WITH_LABEL = 0x00000002,
    GET_RESOURCE_INFO_WITH_ICON = 0x00000004,
    GET_RESOURCE_INFO_WITH_SORTED_BY_LABEL = 0x00000008,
    GET_RESOURCE_INFO_WITH_DRAWABLE_DESCRIPTOR = 0x00000010,
    GET_RESOURCE_INFO_ONLY_WITH_MAIN_ABILITY = 0x00000020
  }

  export native function getBundleResourceInfoNative(bundleName: string, resourceFlags: number, appIndex: number): BundleResourceInfo;

  function getBundleResourceInfo(bundleName: string, resourceFlags?: number): BundleResourceInfo
  {
    let resFlag = resourceFlags ?? INVALID_INT;
    return bundleResourceManager.getBundleResourceInfoNative(bundleName, resFlag, INVALID_INT);
  }

  function getBundleResourceInfo(bundleName: string, resourceFlags?: number, appIndex?: number): BundleResourceInfo
  {
    let resFlag = resourceFlags ?? INVALID_INT;
    let appIdx = appIndex ?? INVALID_INT;
    return bundleResourceManager.getBundleResourceInfoNative(bundleName, resFlag, appIdx);
  }
}