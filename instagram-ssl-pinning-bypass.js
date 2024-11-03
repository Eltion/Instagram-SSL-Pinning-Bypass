'use strict'

//https://github.com/Eltion/Instagram-SSL-Pinning-Bypass/issues/19
function disableHTTP3() {
    try {
        Java.perform(() => {
            const File = Java.use("java.io.File");
            const ActivityThread = Java.use('android.app.ActivityThread');
            Java.scheduleOnMainThread(() => {
                var context = ActivityThread.currentApplication().getApplicationContext();
                const mobileconfigDir = context.getFilesDir().getAbsolutePath().toString() + "/mobileconfig";
                const dir = File.$new(mobileconfigDir);
                for (const session of dir.listFiles()) {
                    if (/\d+\.data$/.test(session.getAbsolutePath())) {
                        if (session.listFiles().length > 0)
                            logger("[*][+] Deleting config files to disable HTTP3. Restart App.")
                        for (const conf of session.listFiles()) {
                            conf.delete();
                        }
                    }
                }
            });
        });
    } catch (e) {
        logger("[*][-] Failed to disable HTTP/3")
    }
}


function hook_proxygen_SSLVerification(library) {
    const verifyFunction = library.enumerateExports().find(el => el.name.includes("verifyWithMetrics"));

    if (!verifyFunction) {
        logger(`[*][-] Failed to find verifyWithMetrics function`);
        return;
    }

    try {
        Interceptor.attach(verifyFunction.address, {
            onLeave: function(retvalue) {
                retvalue.replace(1);
            }
        });
        logger(`[*][+] Hooked function: ${verifyFunction.name}`);
    } catch (err) {
        logger(`[*][-] Failed to hook function: ${verifyFunction.name}`);
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
    Java.perform(function() {
        var Log = Java.use("android.util.Log");
        Log.v("INSTAGRAM_SSL_PINNING_BYPASS", message);
    });
}


logger("[*][*] Waiting for libliger-common...");
waitForModule("libliger-common.so").then((lib) => {
    logger(`[*][+] Found libliger-common at: ${lib.base}`)
    hook_proxygen_SSLVerification(lib);
});

//disableHTTP3();
//Universal Android SSL Pinning Bypass #2
Java.perform(function() {
    try {
        var array_list = Java.use("java.util.ArrayList");
        var ApiClient = Java.use('com.android.org.conscrypt.TrustManagerImpl');
        if (ApiClient.checkTrustedRecursive) {
            logger("[*][+] Hooked checkTrustedRecursive")
            ApiClient.checkTrustedRecursive.implementation = function(a1, a2, a3, a4, a5, a6) {
                var k = array_list.$new();
                return k;
            }
        } else {
            logger("[*][-] checkTrustedRecursive not Found")
        }
    } catch (e) {
        logger("[*][-] Failed to hook checkTrustedRecursive")
    }
});

Java.perform(function() {
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
            name: "com.leftenter.instagram",
        });
        const TrustManagers = [TrustManager.$new()];
        const SSLContextInit = sSLContext.init.overload(
            "[Ljavax.net.ssl.KeyManager;", "[Ljavax.net.ssl.TrustManager;", "java.security.SecureRandom");
        SSLContextInit.implementation = function(keyManager, trustManager, secureRandom) {
            SSLContextInit.call(this, keyManager, TrustManagers, secureRandom);
        };
        logger("[*][+] Hooked SSLContextInit")
    } catch (e) {
        logger("[*][-] Failed to hook SSLContextInit")
    }
})
