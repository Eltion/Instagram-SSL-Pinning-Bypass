# Instagram SSL Pinning Bypass

Bypass Instagram SSL pinning on Android devices.  
Supported ABIs: `x86`, `x86_64`, `armeabi-v7a`, `arm64-v8a`  
Latest version: `v247.0.0.17.113`

## Patched APK (No Root)

Download the latest patched APK: 
+ [instagram-v247.0.0.17.113-x86.apk](https://github.com/Eltion/Instagram-SSL-Pinning-Bypass/releases/download/v247.0.0.17.113/instagram-v247.0.0.17.113-x86.apk)
+ [instagram-v247.0.0.17.113-x86_64.apk](https://github.com/Eltion/Instagram-SSL-Pinning-Bypass/releases/download/v247.0.0.17.113/instagram-v247.0.0.17.113-x86_64.apk)
+ [instagram-v247.0.0.17.113-armeabi-v7a.apk](https://github.com/Eltion/Instagram-SSL-Pinning-Bypass/releases/download/v247.0.0.17.113/instagram-v247.0.0.17.113-armeabi-v7a.apk)
+ [instagram-v247.0.0.17.113-arm64-v8a.apk](https://github.com/Eltion/Instagram-SSL-Pinning-Bypass/releases/download/v247.0.0.17.113/instagram-v247.0.0.17.113-arm64-v8a.apk)

[See all versions](https://github.com/Eltion/Instagram-SSL-Pinning-Bypass/releases/)

## Run using Frida (Requires Root)

This method requires frida-tools and also frida-server running in the device
```
frida -U -l .\instagram-ssl-pinning-bypass.js -f com.instagram.android --no-pause
```

## Patch APK

You can create your own patched APK. 


### Requirements Linux (Ubuntu):
1. Install java JRE: `sudo apt install default-jre`
2. Install apksigner: `sudo apt install apksigner`
3. Install zipalign: `sudo apt install zipalign`  

Note: apksigner and zipalign can also be found in android sdk [build-tools](https://dl.google.com/android/repository/build-tools_r30.0.1-linux.zip)

### Requirements Windows:
1. Install java JRE
2. Download [build-tools](https://dl.google.com/android/repository/build-tools_r30.0.1-windows.zip) and unzip
3. Add unzip folder to path variable

### Instructions

1. Download instagram apk file.
2. Install requirements > `pip install -r requirements.txt`
3. Run script > `python patch_apk.py -i <input apk> -o <output apk>`

After that an patched apk file should be generated.

## Intercept network traffic

You can use a tool like mitmproxy or Burp Suite to intercept the network.

1. Install patched APK in the device
2. Install [mitmproxy](https://mitmproxy.org/) or [Burp Suite](https://portswigger.net/burp)
3. Set up proxy for wifi settings or run: `adb shell settings put global http_proxy <proxy>`

Now you should be able to see the network traffic.

### Video tutorial using mitmproxy
https://user-images.githubusercontent.com/18504798/177385493-5fd557bd-cb59-4342-b6d8-8b70262e6c06.mp4


## View script logs
To view the logcat run:
```
adb logcat -s "INSTAGRAM_SSL_PINNING_BYPASS:V"
```

[#leftenter](#leftenter)
