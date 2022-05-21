'use strict'
function hook_proxygen_SSLVerification(library){
    const functionName = "_ZN8proxygen15SSLVerification17verifyWithMetricsEbP17x509_store_ctx_stRKNSt6__ndk112basic_stringIcNS3_11char_traitsIcEENS3_9allocatorIcEEEEPNS0_31SSLFailureVerificationCallbacksEPNS0_31SSLSuccessVerificationCallbacksERKNS_15TimeUtilGenericINS3_6chrono12steady_clockEEERNS_10TraceEventE";
    
    const f = Module.getExportByName(library.name, functionName);
    if(!f){
        console.error(`[*][*] Could not find function: ${functionName}`);
        return;
    }
    Interceptor.attach(f, {
        onLeave: function (retvalue) {
            retvalue.replace(1);
        }
    });

    console.log(`[*][*] Hooked function: ${functionName}`);
}

function hook_X509_verify_cert(library){
    const functionName = "X509_verify_cert";
    const f = Module.getExportByName(library.name, functionName);
    if(!f){
        console.error(`[*][*] Could not find function: ${functionName}`);
        return;
    }
    Interceptor.attach(f, {
        onLeave: function (retvalue) {
            retvalue.replace(1);
        }
    });

    console.log(`[*][*] Hooked function: ${functionName}`);
}

async function waitForModule(moduleName){
    return new Promise(resolve => {
        const interval = setInterval(() => {
            const libliger = Process.findModuleByName(moduleName);
            if(libliger != null){
                clearInterval(interval);
                resolve(libliger);
            }
        },300);
    });
}

console.log("[*][*] Wating for libliger...");
waitForModule("libliger.so").then((lib) => {
    console.log(`[*][*] Found libliger at: ${lib.base}`)
    hook_proxygen_SSLVerification(lib);
    hook_X509_verify_cert(lib);
});



