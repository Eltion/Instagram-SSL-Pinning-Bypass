# Instagram SSL Pinning Bypass

Bypass Instagram SSL pinning on Android devices.

## Patched apk (No Root)

Download latest pached apk:  
+ [instagram-v237.0.0.14.102-x86.apk](https://github.com/Eltion/Instagram-SSL-Pinning-Bypass/releases/download/v237.0.0.14.102/instagram-v237.0.0.14.102-x86.apk)
+ [instagram-v237.0.0.14.102-x86_64.apk](https://github.com/Eltion/Instagram-SSL-Pinning-Bypass/releases/download/v237.0.0.14.102/instagram-v237.0.0.14.102-x86_64.apk)

[See all versions](https://github.com/Eltion/Instagram-SSL-Pinning-Bypass/releases/)

## Patch apk (No Root)

This method will create a patched apk.

1. Download instagram apk file.
2. Install requirements.  
  `pip install -r requirements.txt`
3. Run command.   
`python patch_apk.py -i <input apk> -o <output apk>`

## Run using Frida (Requires Root)

This method requires frida-tools and also frida-server running in the device
```
frida -U -l .\instagram-ssl-pinning-bypass.js -f com.instagram.android --no-pause
```







