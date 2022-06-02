import json
import lzma
import lief
from zipfile import ZipFile
import shutil
import os
import requests
import sys
import argparse


TEMP_FOLDER = os.getcwd() + "/temp"
DEFAULT_OUTPUT_NAME = "app_patched.apk"
SUPPORTED_ARCHS = ["x86"]


def inject_frida_gadget(libpath):
    print("Patching:", libpath)
    libnative = lief.parse(libpath)
    libnative.add_library("libgadget.so")
    libnative.write(libpath)


def create_temp_folder():
    delete_temp_folder()
    os.mkdir(TEMP_FOLDER)


def delete_temp_folder():
    if(os.path.exists(TEMP_FOLDER)):
        shutil.rmtree(TEMP_FOLDER)


def get_app_arch(apk):
    res = []
    with ZipFile(apk, "r") as zip_file:
        for filename in zip_file.namelist():
            if filename.startswith("lib/x86/") and "x86" not in res:
                res.append("x86")
            elif filename.startswith("lib/x86_64/") and "x86_64" not in res:
                res.append("x86_64")
            elif filename.startswith("lib/armeabi-v7a/") and "armeabi-v7a" not in res:
                res.append("armeabi-v7a")
            elif filename.startswith("lib/arm64-v8a/") and "arm64-v8a" not in res:
                res.append("arm64-v8a")
    return res


def extract_libs_for_apk(apk, arch):
    libs = ["libelf.so","libfb.so"]
    with ZipFile(apk) as zip_file:
        namelist = zip_file.namelist()
        for lib in libs:
            libname = "lib/{0}/{1}".format(arch, lib)
            if libname in namelist:
                print("Extracting:", libname)
                return zip_file.extract(libname, TEMP_FOLDER)


def get_arch(apk):
    app_archs = get_app_arch(apk)
    print("App ABIs: ", app_archs)
    archs = list(set(app_archs) & set(SUPPORTED_ARCHS))
    print("Supported ABIs: ", archs)
    return archs


def copy_apk_to_temp_folder(apk_path):
    filepath = os.path.join(TEMP_FOLDER, "app.apk")
    shutil.copy(apk_path, filepath)
    return filepath


def download_file(url, filename):
    filepath = os.path.join(TEMP_FOLDER, filename)
    with open(filepath, "wb") as f:
        print("Downloading %s" % filename)
        response = requests.get(url, stream=True)
        total_length = response.headers.get('content-length')
        if total_length is None:
            f.write(response.content)
        else:
            dl = 0
            total_length = int(total_length)
            for data in response.iter_content(chunk_size=4096):
                dl += len(data)
                f.write(data)
                done = int(50 * dl / total_length)
                sys.stdout.write("\r[%s%s]" % ('=' * done, ' ' * (50-done)))
                sys.stdout.flush()
    print("\n")
    return filepath


def extract_frida_gadget(archive_path, arch):
    filepath = os.path.join(TEMP_FOLDER, "lib", arch, "libgadget.so")
    with lzma.open(archive_path, mode='rb') as archive:
        with open(filepath, "wb") as f:
            f.write(archive.read())

    os.remove(archive_path)
    return filepath


def download_frida_gadget(arch):
    arch_config = {
        "x86":"x86",
        "x86_64":"x86_64",
        "armeabi-v7a":"arm",
        "arm64-v8a": "arm64"
    }
    response = requests.get(
        "https://api.github.com/repos/frida/frida/releases").text
    releases = json.loads(response)
    latest_release = releases[0]
    tag_name = latest_release["tag_name"]
    frida_gadget_url = "https://github.com/frida/frida/releases/download/{0}/frida-gadget-{0}-android-{1}.so.xz".format(
        tag_name, arch_config[arch])
    archive_path = download_file(
        frida_gadget_url, "firda-gadget-{0}-{1}.so.xz".format(tag_name, arch))
    return extract_frida_gadget(archive_path, arch)


def patch_apk(apk):
    print("Rebuilding apk file...")
    apk_in = ZipFile(apk, "r")
    apk_out = ZipFile(os.path.join(TEMP_FOLDER, "new_apk.apk"), "w")
    files = apk_in.namelist()
    for file in files:
        if not os.path.exists(os.path.join(TEMP_FOLDER, file)):
            apk_out.writestr(file, apk_in.read(file))
    apk_in.close()
    libfolder = os.path.join(TEMP_FOLDER, "lib")
    for (root, _, files) in os.walk(libfolder, topdown=True):
        for filename in files:
            filepath = os.path.join(root, filename)
            archname = os.path.relpath(filepath, TEMP_FOLDER)
            apk_out.write(filepath, archname)
    apk_out.close()
    return apk_out.filename


def copy_script_temp():
    src = os.path.join(os.getcwd(), "instagram-ssl-pinning-bypass.js")
    # added lib prefix and so extension so script is copied into /data/data/com.instagram.android/lib
    dest = os.path.join(TEMP_FOLDER, "libsslbypass.js.so")
    return shutil.copy(src, dest)


def create_config_file():
    filepath = os.path.join(TEMP_FOLDER, "libgadget.config.so")
    config = {
        "interaction": {
            "type": "script",
            "path": "./libsslbypass.js.so"
        }
    }
    with open(filepath, 'w') as f:
        json.dump(config, f)
        return filepath


def main():
    parser = argparse.ArgumentParser(
        description='Remove ssl pining from instagram app')
    parser.add_argument("-i", "--input", type=str,
                        help="Input apk file", required=True)
    parser.add_argument("-o", "--output", type=str,
                        help="Output apk file", default=DEFAULT_OUTPUT_NAME)
    args = parser.parse_args()
    inputfile = args.input
    outputfile = args.output
    create_temp_folder()
    temp_apk = copy_apk_to_temp_folder(inputfile)

    archs = get_arch(temp_apk)
    if len(archs) == 0:
        print("Current ABI is not supported!")
        exit(1)
    config_file = create_config_file()
    print("Created config_file at: ", config_file)
    script = copy_script_temp()
    print("Created script_file at: ", script)
    for arch in archs:
        print("\nPatching for", arch)
        nativelib = extract_libs_for_apk(temp_apk, arch)
        arch_folder = os.path.join(TEMP_FOLDER, "lib", arch)
        download_frida_gadget(arch)
        inject_frida_gadget(nativelib)
        shutil.copy(config_file, arch_folder)
        shutil.copy(script, arch_folder)
    output = patch_apk(temp_apk)
    outputpath = shutil.move(output, outputfile)
    delete_temp_folder()
    print("Sucessful. Patched file at:", outputpath)


main()
