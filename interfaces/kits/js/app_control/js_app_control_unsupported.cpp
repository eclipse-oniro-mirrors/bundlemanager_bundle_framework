#include "js_app_control.h"

#include <string>

#include "app_log_wrapper.h"
#include "bundle_errors.h"
#include "business_error.h"
#include "common_func.h"

namespace OHOS {
namespace AppExecFwk {
napi_value GetDisposedStatus(napi_env env, napi_callback_info info)
{
    APP_LOGE("SystemCapability.BundleManager.BundleFramework.AppControl not supported.");
    napi_value error = BusinessError::CreateCommonError(env, ERROR_SYSTEM_ABILITY_NOT_FOUND,
        "getDisposedStatus");
    napi_throw(env, error);
    return nullptr;
}

napi_value SetDisposedStatus(napi_env env, napi_callback_info info)
{
    APP_LOGE("SystemCapability.BundleManager.BundleFramework.AppControl not supported.");
    napi_value error = BusinessError::CreateCommonError(env, ERROR_SYSTEM_ABILITY_NOT_FOUND,
        "setDisposedStatus");
    napi_throw(env, error);
    return nullptr;
}

napi_value DeleteDisposedStatus(napi_env env, napi_callback_info info)
{
    APP_LOGE("SystemCapability.BundleManager.BundleFramework.AppControl not supported.");
    napi_value error = BusinessError::CreateCommonError(env, ERROR_SYSTEM_ABILITY_NOT_FOUND,
        "deleteDisposedStatus");
    napi_throw(env, error);
    return nullptr;
}
} // AppExecFwk
} // OHOS
