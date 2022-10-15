#include "distributed_bundle.h"

#include <string>

#include "app_log_wrapper.h"
#include "bundle_errors.h"
#include "business_error.h"
#include "common_func.h"

namespace OHOS {
namespace AppExecFwk {
napi_value GetRemoteAbilityInfo(napi_env env, napi_callback_info info)
{
    APP_LOGE("SystemCapability.BundleManager.DistributedBundleFramework not supported.");
    napi_value error = BusinessError::CreateCommonError(env, ERROR_SYSTEM_ABILITY_NOT_FOUND,
        "getRemoteAbilityInfo");
    napi_throw(env, error);
    return nullptr;
}
} // AppExecFwk
} // OHOS
