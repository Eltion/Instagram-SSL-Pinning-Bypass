'use strict'

//Disable HTTP3. Currently will only work on verion 260.0.0.23.115
Java.perform(function () {
    try {
        const X01p = Java.use("X.01s") // Use X.01p for arm64
        X01p.A01.implementation = function (...args) {
            const res = this.A01(...args);
            if (args[2] == 36320124650655855) {
                logger("[*][+] Forced HTTP2")
                return Java.use("java.lang.Boolean").$new(false);
            }
            return res;
        }
    } catch(e) {
        logger("[*][+] Failed to force HTTP2")
    }
})


function hook_proxygen_SSLVerification(library) {
    const functionName = "_ZN8proxygen15SSLVerification17verifyWithMetricsEbP17x509_store_ctx_stRKNSt6__ndk112basic_stringIcNS3_11char_traitsIcEENS3_9allocatorIcEEEEPNS0_31SSLFailureVerificationCallbacksEPNS0_31SSLSuccessVerificationCallbacksERKNS_15TimeUtilGenericINS3_6chrono12steady_clockEEERNS_10TraceEventE";

    try {
        const f = Module.getExportByName(library.name, functionName);

        Interceptor.attach(f, {
            onLeave: function (retvalue) {
                retvalue.replace(1);
            }
        });
        logger(`[*][+] Hooked function: ${functionName}`);
    } catch (err) {
        logger(`[*][-] Failed to hook function: ${functionName}`);
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
    logger(`[*][+] Found libliger at: ${lib.base}`)
    hook_proxygen_SSLVerification(lib);
});

//Universal Android SSL Pinning Bypass #2
Java.perform(function () {
    try {
        var array_list = Java.use("java.util.ArrayList");
        var ApiClient = Java.use('com.android.org.conscrypt.TrustManagerImpl');
        if (ApiClient.checkTrustedRecursive) {
            logger("[*][+] Hooked checkTrustedRecursive")
            ApiClient.checkTrustedRecursive.implementation = function (a1, a2, a3, a4, a5, a6) {
                var k = array_list.$new();
                return k;
            }
        } else {
            logger("[*][-] checkTrustedRecursive not Found")
        }
    } catch(e) {
        logger("[*][-] Failed to hook checkTrustedRecursive")
    }
});

Java.perform(function () {
    try {
        const x509TrustManager = Java.use("javax.net.ssl.X509TrustManager");
        const sSLContext = Java.use("javax.net.ssl.SSLContext");
        const TrustManager = Java.registerClass({
            implements: [x509TrustManager],
            methods: {
                checkClientTrusted(chain, authType) {
                },
                checkServerTrusted(chain, authType) {
                },
                getAcceptedIssuers() {
                    return [];
                },
            },
            name: "com.leftenter.tiktok",
        });
        const TrustManagers = [TrustManager.$new()];
        const SSLContextInit = sSLContext.init.overload(
            "[Ljavax.net.ssl.KeyManager;", "[Ljavax.net.ssl.TrustManager;", "java.security.SecureRandom");
        SSLContextInit.implementation = function (keyManager, trustManager, secureRandom) {
            SSLContextInit.call(this, keyManager, TrustManagers, secureRandom);
        };
        logger("[*][+] Hooked SSLContextInit")
    } catch (e) {
        logger("[*][-] Failed to hook SSLContextInit")
    }
})
