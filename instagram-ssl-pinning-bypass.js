'use strict'

function hook_proxygen_SSLVerification(library) {
    const functionName = "_ZN8proxygen15SSLVerification17verifyWithMetricsEbP17x509_store_ctx_stRKNSt6__ndk112basic_stringIcNS3_11char_traitsIcEENS3_9allocatorIcEEEEPNS0_31SSLFailureVerificationCallbacksEPNS0_31SSLSuccessVerificationCallbacksERKNS_15TimeUtilGenericINS3_6chrono12steady_clockEEERNS_10TraceEventE";

    try {
        const f = Module.getExportByName(library.name, functionName);

        Interceptor.attach(f, {
            onLeave: function (retvalue) {
                retvalue.replace(1);
            }
        });
        logger(`[*][*] Hooked function: ${functionName}`);
    } catch (err) {
        logger(`[*][*] Failed to hook function: ${functionName}`);
        logger(err.toString())
    }
}

function hook_X509_verify_cert(library) {
    const functionName = "X509_verify_cert";
    try {
        const f = Module.getExportByName(library.name, functionName);
        Interceptor.attach(f, {
            onLeave: function (retvalue) {
                retvalue.replace(1);
            }
        });

        logger(`[*][*] Hooked function: ${functionName}`);

    } catch (err) {
        logger(`[*][*] Failed to hook function: ${functionName}`);
        logger(err.toString())
    }

}

function waitForModule(moduleName) {
    return new Promise(resolve => {
        const interval = setInterval(() => {
            const module = Process.findModuleByName(moduleName);
            if (module != null) {
                clearInterval(interval);
                resolve(module);
            }
        }, 300);
    });
}

function logger(message) {
    console.log(message);
    Java.perform(function () {
        var Log = Java.use("android.util.Log");
        Log.v("INSTAGRAM_SSL_PINNING_BYPASS", message);
    });
}


logger("[*][*] Waiting for libliger...");
waitForModule("libliger.so").then((lib) => {
    logger(`[*][*] Found libliger at: ${lib.base}`)
    hook_proxygen_SSLVerification(lib);
    hook_X509_verify_cert(lib);
});