/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

import Ability from '@ohos.app.ability.UIAbility'
import appControl from '@ohos.bundle.appControl'

export default class MainAbility extends Ability {
    onCreate(want,launchParam){
        // Ability is creating, initialize resources for this ability
        console.log("[LPCDemo] MainAbility onCreate")
        globalThis.abilityWant = want;
    }

    onStart() {
        var appId = "com.example.otaupdatetest";
        var want1 = {bundleName: 'com.example.otaupdatetest111'};

        try {
            appControl.setDisposedStatusSync(appId, want1)
                .then(() => {
                    console.info('[LPCDemo] setDisposedStatusSync success');
                }).catch((error) => {
                    console.error('[LPCDemo] setDisposedStatusSync failed ' + error.message);
                });
        } catch (error) {
            console.error('[LPCDemo] setDisposedStatusSync failed ' + error.message);
        }

        try {
            appControl.deleteDisposedStatusSync(appId)
                .then(() => {
                    console.info('[LPCDemo] deleteDisposedStatusSync success');
                }).catch((error) => {
                    console.error('[LPCDemo] deleteDisposedStatusSync failed ' + error.message);
                });
        } catch (error) {
            console.error('[LPCDemo] deleteDisposedStatusSync failed ' + error.message);
        }

        var data;
        try {
            appControl.getDisposedStatusSync(appId)
                .then((data) => {
                    console.info('[LPCDemo] getDisposedStatusSync success. DisposedStatus: ' + JSON.stringify(data));
                }).catch((error) => {
                    console.error('[LPCDemo] getDisposedStatusSync failed ' + error.message);
                });
        } catch (error) {
            console.error('[LPCDemo] getDisposedStatusSync failed ' + error.message);
        }
    }

    onDestroy() {
        // Ability is destroying, release resources for this ability
        console.log("[Demo] MainAbility onDestroy")
    }

    onWindowStageCreate(windowStage) {
        // Main window is created, set main page for this ability
        console.log("[Demo] MainAbility onWindowStageCreate")
        globalThis.abilityContext = this.context
        windowStage.setUIContent(this.context, "pages/index", null)
    }

    onWindowStageDestroy() {
        //Main window is destroyed, release UI related resources
        console.log("[Demo] MainAbility onWindowStageDestroy")
    }

    onForeground() {
        // Ability has brought to foreground
        console.log("[Demo] MainAbility onForeground")
    }

    onBackground() {
        // Ability has back to background
        console.log("[Demo] MainAbility onBackground")
    }
};