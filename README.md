# Instagram SSL Pinning Bypass

Bypass Instagram SSL pinning on Android devices.

## Patched APK (No Root)

Download the latest patched APK:  
+ [instagram-v237.0.0.14.102-x86.apk](https://github.com/Eltion/Instagram-SSL-Pinning-Bypass/releases/download/v237.0.0.14.102/instagram-v237.0.0.14.102-x86.apk)
+ [instagram-v237.0.0.14.102-x86_64.apk](https://github.com/Eltion/Instagram-SSL-Pinning-Bypass/releases/download/v237.0.0.14.102/instagram-v237.0.0.14.102-x86_64.apk)

[See all versions](https://github.com/Eltion/Instagram-SSL-Pinning-Bypass/releases/)

## Patch APK (No Root)

With this method, you can create your own patched APK.

1. Download instagram apk file.
2. Install requirements > `pip install -r requirements.txt`
3. Run script > `python patch_apk.py -i <input apk> -o <output apk>`
4. Install output apk file


## Run using Frida (Requires Root)

This method requires frida-tools and also frida-server running in the device
```
frida -U -l .\instagram-ssl-pinning-bypass.js -f com.instagram.android --no-pause
```

## Intercept network traffic

You can use a tool like mitmproxy or Burp Suite to intercept the network.

1. Install patched APK in the device
2. Install [mitmproxy](https://mitmproxy.org/) or [Burp Suite](https://portswigger.net/burp)
3. Set up proxy for wifi settings or run: `adb shell settings put global http_proxy <proxy>`

Now you should be able to see the network traffic.

## View script logs
To view the logcat run:
```
adb logcat -s "SSL_PINNING_BYPASS:V"
```
## TODO
Add support for `armeabi-v7a` and `arm64-v8a`

[#leftenter]()
