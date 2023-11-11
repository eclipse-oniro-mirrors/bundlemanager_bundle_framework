/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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
 * @addtogroup Native_Bundle
 * @{
 *
 * @brief Describes the Native Bundle.
 *
 * @since 9
 * @version 1.0
 */

/**
 * @file native_interface_bundle.h
 *
 * @brief Declares the <b>Bundle</b>-specific function, including function for obtaining application info.
 *
 * @since 9
 * @version 1.0
 */
#ifndef FOUNDATION_APPEXECFWK_STANDARD_KITS_APPKIT_NATIVE_BUNDLE_INCLUDE_NATIVE_INTERFACE_BUNDLE_H
#define FOUNDATION_APPEXECFWK_STANDARD_KITS_APPKIT_NATIVE_BUNDLE_INCLUDE_NATIVE_INTERFACE_BUNDLE_H

#ifdef __cplusplus
extern "C" {
#endif
struct OH_NativeBundle_ApplicationInfo {
    /**
     * Indicates the name of application
     * @syscap SystemCapability.BundleManager.BundleFramework.Core
     * @since 9
     */
    char* bundleName;

    /**
     * Indicates the fingerprint of application
     * @syscap SystemCapability.BundleManager.BundleFramework.Core
     * @since 9
     */
    char* fingerprint;

    /**
     * Indicates the ID of the application to which this bundle belongs
     * The application ID uniquely identifies an application. It is determined by the bundle name and signature
     * @syscap SystemCapability.BundleManager.BundleFramework.Core
     * @since 11
     */
    char* appId;

    /**
     * Globally unique identifier of an application.
     * AppIdentifier does not change along the application lifecycle, including version updates, certificate changes,
     * public and private key changes, and application transfer.
     * @syscap SystemCapability.BundleManager.BundleFramework.Core
     * @since 11
     */
    char* appIdentifier;
};

/**
 * @brief Obtains the application info based on the The current bundle.
 *
 * @return Returns the application info.
 * @since 9
 * @version 1.0
 */
OH_NativeBundle_ApplicationInfo OH_NativeBundle_GetCurrentApplicationInfo();

#ifdef __cplusplus
};
#endif
#endif // FOUNDATION_APPEXECFWK_STANDARD_KITS_APPKIT_NATIVE_BUNDLE_INCLUDE_NATIVE_INTERFACE_BUNDLE_H
