/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

/**
 * This module is used to obtain bundle resource information of various applications installed on the current device.
 *
 * @namespace bundleResourceManager
 * @syscap SystemCapability.BundleManager.BundleFramework.Resource
 * @systemapi
 * @since 11
 */
export default namespace bundleResourceManager {

  loadLibrary("ani_bundle_res_manager.z");

  /**
   * Used to query the enumeration value of resource info. Multiple values can be passed in the form.
   *
   * @enum { number }
   * @syscap SystemCapability.BundleManager.BundleFramework.Resource
   * @systemapi
   * @since 11
   */
  enum ResourceFlag {
    /**
     * Used to obtain the resource info contains label and icon.
     *
     * @syscap SystemCapability.BundleManager.BundleFramework.Resource
     * @systemapi
     * @since 11
     */
    GET_RESOURCE_INFO_ALL = 0x00000001,

    /**
     * Used to obtained the label resource info.
     *
     * @syscap SystemCapability.BundleManager.BundleFramework.Resource
     * @systemapi
     * @since 11
     */
    GET_RESOURCE_INFO_WITH_LABEL = 0x00000002,

    /**
     * Used to obtained the icon resource info.
     *
     * @syscap SystemCapability.BundleManager.BundleFramework.Resource
     * @systemapi
     * @since 11
     */
    GET_RESOURCE_INFO_WITH_ICON = 0x00000004,

    /**
     * Used to obtain the resource info sorted by label.
     * It can't be used alone, it needs to be used with GET_RESOURCE_INFO_ALL or GET_RESOURCE_INFO_WITH_LABEL.
     *
     * @syscap SystemCapability.BundleManager.BundleFramework.Resource
     * @systemapi
     * @since 11
     */
    GET_RESOURCE_INFO_WITH_SORTED_BY_LABEL = 0x00000008,

    /**
     * Used to obtain bundle icon drawable descriptor.
     *
     * @syscap SystemCapability.BundleManager.BundleFramework.Resource
     * @systemapi
     * @since 12
     */
    GET_RESOURCE_INFO_WITH_DRAWABLE_DESCRIPTOR = 0x00000010
  }

  /**
   * Obtains the BundleResourceInfo of a specified bundle. Default resourceFlag is GET_RESOURCE_INFO_ALL.
   *
   * @permission ohos.permission.GET_BUNDLE_RESOURCES
   * @param { string } bundleName - Indicates the bundle name of the application.
   * @param { number } [resourceFlags] - Indicates the flag used to specify information contained in the BundleResourceInfo object that will be returned.
   * @param { number } [appIndex] - Indicates the index of the bundle.
   * @returns { BundleResourceInfo } Returns the BundleResourceInfo object.
   * @throws { BusinessError } 201 - Permission denied.
   * @throws { BusinessError } 202 - Permission denied, non-system app called system api.
   * @throws { BusinessError } 401 - Parameter error. Possible causes: 1. Mandatory parameters are left unspecified; 2. Incorrect parameter types.
   * @throws { BusinessError } 17700001 - The specified bundleName is not found.
   * @throws { BusinessError } 17700061 - AppIndex not in valid range or not found.
   * @syscap SystemCapability.BundleManager.BundleFramework.Resource
   * @systemapi
   * @since 12
   */
  export function getBundleResourceInfo(bundleName: string, resourceFlags?: number, appIndex?: number): BundleResourceInfo
  {
      let resFlag = resourceFlags ?? -500;
      let appIdx = appIndex ?? -500;
      return bundleResourceManager.getBundleResourceInfo(bundleName, resFlag as int, appIdx as int);
  }

  native function getBundleResourceInfo(bundleName: string, resourceFlags: int, appIndex: int): BundleResourceInfo;
}