# Instagram SSL Pinning Bypass

Use to bypass Instagram SSL pinning on Android devices.

## Patch apk (No Root Required)

This method will create a patched apk.

1. Download instagram apk file.
2. Install requirements.  
  `pip install -r requirements.txt`
3. Run command.   
`python patch_apk.py -i <input apk> -o <output apk>`

## Run using Frida (Requires root)

This method requires frida-tools and also frida-server running in the device
```
frida -U -l .\instagram-ssl-pinning-bypass.js -f com.instagram.android --no-pause
```







