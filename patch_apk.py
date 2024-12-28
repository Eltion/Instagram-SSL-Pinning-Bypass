import json
import lzma
import zipfile
from zipfile import ZipFile
import shutil
import os
import requests
import sys
import argparse
from shutil import which
import subprocess

TEMP_FOLDER = os.getcwd() + "/temp"
DEFAULT_OUTPUT_NAME = "app_patched.apk"
SUPPORTED_ARCHS = ["x86","x86_64","armeabi-v7a","arm64-v8a"]


def _determine_end_of_smali_method_from_line(smali: list, start: int) -> int:
        end_methods = [(i + start) for i, x in enumerate(smali[start:]) if '.end method' in x]

        if len(end_methods) <= 0:
            raise Exception('Unable to find the end of the existing constructor')

        end_of_method = end_methods[0] - 1

        if 'return' in smali[end_of_method]:
            end_of_method -= 1

        return end_of_method

def _determine_smali_path_for_class(target_class) -> str:
        target_class = target_class.replace('.', '/')

        activity_path = os.path.join(TEMP_FOLDER, 'app', 'smali', target_class) + '.smali'
        if not os.path.exists(activity_path):
            for x in range(2, 100):
                smali_path = os.path.join(TEMP_FOLDER, 'app', 'smali_classes{0}'.format(x))
                if not os.path.exists(smali_path):
                    break

                activity_path = os.path.join(smali_path, target_class) + '.smali'

                if os.path.exists(activity_path):
                    break

        if not os.path.exists(activity_path):
            raise Exception('Unable to find smali to patch!')

        return activity_path

def _determine_first_inject_point_of_smali_method_from_line(smali: list, start: int) -> int:
        pos = start
        in_annotation = False
        while pos + 1 < len(smali):
            pos = pos + 1
            line = smali[pos].strip()

            if not line:
                continue

            if line.startswith(".locals "):
                continue

            if in_annotation or line.startswith(".annotation "):
                in_annotation = True
                continue

            if line.startswith(".end annotation"):
                in_annotation = False
                continue

            return pos - 1

def _patch_smali_with_load_library(smali_lines: list, inject_marker: int) -> list:
    full_load_library = ('.method static constructor <clinit>()V\n'
                         '   .locals 0\n'  # _revalue_locals_count() will ++ this
                         '\n'
                         '   .prologue\n'
                         '   const-string v0, "gadget"\n'
                         '\n'
                         '   invoke-static {v0}, Ljava/lang/System;->loadLibrary(Ljava/lang/String;)V\n'
                         '\n'
                         '   return-void\n'
                         '.end method\n')

    partial_load_library = ('\n    const-string v0, "gadget"\n'
                            '\n'
                            '    invoke-static {v0}, Ljava/lang/System;->loadLibrary(Ljava/lang/String;)V\n')

    if 'clinit' in smali_lines[inject_marker]:

        inject_point = _determine_first_inject_point_of_smali_method_from_line(smali_lines, inject_marker)

        patched_smali = \
            smali_lines[:inject_point] + partial_load_library.splitlines(keepends=True) + \
            smali_lines[inject_point:]

    else:
        patched_smali = \
            smali_lines[:inject_marker] + full_load_library.splitlines(keepends=True) + smali_lines[inject_marker:]

    return patched_smali

def _revalue_locals_count(patched_smali: list, inject_marker: int):
    end_of_method = _determine_end_of_smali_method_from_line(patched_smali, inject_marker)

    defined_locals = [i for i, x in enumerate(patched_smali[inject_marker:end_of_method])
                      if '.locals' in x]

    if len(defined_locals) <= 0:
        return patched_smali

    locals_smali_offset = defined_locals[0] + inject_marker

    try:
        defined_local_value = patched_smali[locals_smali_offset].split(' ')[-1]
        defined_local_value_as_int = int(defined_local_value, 10)
        new_locals_value = defined_local_value_as_int + 1

    except ValueError as e:
        return patched_smali

    patched_smali[locals_smali_offset] = patched_smali[locals_smali_offset].replace(
        str(defined_local_value_as_int), str(new_locals_value))

    return patched_smali

# Function to inject a library into a target process.
# Credits: This implementation is based on code from the objection project.
# Repository: https://github.com/sensepost/objection
def inject_load_library(mainClass: str):

    smaliFile = _determine_smali_path_for_class(mainClass);

    with open(smaliFile, 'r') as f:
        smali_lines = f.readlines()

    inject_marker = [i for i, x in enumerate(smali_lines) if '# direct methods' in x]

    if len(inject_marker) <= 0:
        raise Exception('Unable to determine position to inject a loadLibrary call')

    inject_marker = inject_marker[0] + 1

    patched_smali = _patch_smali_with_load_library(smali_lines, inject_marker)
    patched_smali = _revalue_locals_count(patched_smali, inject_marker)

    print("Patched smali code: " + smaliFile)

    with open(smaliFile, 'w') as f:
        f.write(''.join(patched_smali))


def create_temp_folder():
    delete_temp_folder()
    os.mkdir(TEMP_FOLDER)

def is_tool_installed(name):
    return which(name) is not None

def check_tools():
    if not is_tool_installed("keytool"):
        print("keytool not installed or not in PATH")
        return False
    if not is_tool_installed("apksigner"):
        print("apksigner not installed or not in PATH")
        return False
    if not is_tool_installed("zipalign"):
        print("zipalign not installed or not in PATH")
        return False
    if not is_tool_installed("apktool"):
        print("apktool not installed or not in PATH")
        return False
    return True

def unpack_apk(apk):
    out = os.path.join(TEMP_FOLDER, "app")
    subprocess.call('apktool d -r -f {0} -o {1}'.format(apk, out), shell=True)

def pack_apk():
    input = os.path.join(TEMP_FOLDER, "app")
    output = os.path.join(TEMP_FOLDER, "new_app.apk")
    subprocess.call('apktool b {0} -o {1}'.format(input, output), shell=True)
    return output

def create_keystore(keyalias, storepass):
    print("Generating keystore...")
    keystore_file = "{0}/release.keystore".format(TEMP_FOLDER)
    subprocess.call(
                'keytool -genkey -v -keystore {0} -alias {1} -keyalg RSA -keysize 2048 -validity 8000 -dname '
                '"CN=com.leftenter.android, OU=ID, O=APK, L=Unknown, S=Unknown, C=XK" -storepass {2}'.format(keystore_file, keyalias, storepass),
                shell=True)
    shutil.copy(keystore_file, "release.keystore")
    return keystore_file

def sign_apk(apk, keystore, key_alias, store_pass):
    print("Signing apk...")
    subprocess.call(
        "apksigner sign -ks {0} --ks-key-alias {1} --ks-pass pass:{2} {3}".format(keystore, key_alias, store_pass, apk),
        shell=True
    )

def zip_align_apk(apk):
    print("Running zipalign...")
    tmp_apk = apk.replace(".apk","_tmp.apk")
    shutil.move(apk, tmp_apk)
    subprocess.call('zipalign -p -f 4 {0} {1}'.format(tmp_apk, apk), stderr=subprocess.STDOUT, shell=True)
    os.remove(tmp_apk)
    

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
    filepath = os.path.join(TEMP_FOLDER, "app" ,"lib", arch, "libgadget.so")
    with lzma.open(archive_path, mode='rb') as archive:
        with open(filepath, "wb") as f:
            f.write(archive.read())

    os.remove(archive_path)
    return filepath


def download_frida_gadget(arch, version):
    arch_config = {
        "armeabi-v7a":"arm",
        "arm64-v8a": "arm64",
        "x86": "x86",
        "x86_64": "x86_64"
    }
    response = requests.get(
        "https://api.github.com/repos/frida/frida/releases").text
    releases = json.loads(response)
    for release in releases:
        tag_name = release["tag_name"]
        if(version and not tag_name == version):
            continue
        for asset in release["assets"]:
            if asset["name"] == "frida-gadget-{0}-android-{1}.so.xz".format(tag_name, arch_config[arch]):
                frida_gadget_url = asset["browser_download_url"]
                archive_path = download_file(
                    frida_gadget_url, "firda-gadget-{0}-{1}.so.xz".format(tag_name, arch))
                return extract_frida_gadget(archive_path, arch)
    raise Exception("Frida version not found!")

def patch_apk(apk):
    print("Rebuilding apk file...")
    apk_in = ZipFile(apk, "r")
    apk_out = ZipFile(os.path.join(TEMP_FOLDER, "new_apk.apk"), "w")
    files = apk_in.infolist()
    for file in files:
        if not os.path.exists(os.path.join(TEMP_FOLDER, file.filename)) and not file.filename.startswith("META-INF\\"):
            apk_out.writestr(file.filename, apk_in.read(file.filename), compress_type=file.compress_type, compresslevel=9)
    apk_in.close()
    libfolder = os.path.join(TEMP_FOLDER, "lib")
    for (root, _, files) in os.walk(libfolder, topdown=True):
        for filename in files:
            filepath = os.path.join(root, filename)
            archname = os.path.relpath(filepath, TEMP_FOLDER)
            apk_out.write(filepath, archname, compress_type=zipfile.ZIP_DEFLATED, compresslevel=9)
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
                        help="Input apk file.", required=True)
    parser.add_argument("-o", "--output", type=str,
                        help="Output apk file.", default=DEFAULT_OUTPUT_NAME)
    parser.add_argument("--keystore", type=str,
                        help="Use your own keystore for signing.")
    parser.add_argument("--keyalias", type=str,
                        help="Key alias", default="PATCH")
    parser.add_argument("--storepass", type=str,
                        help="Password for keystore", default="password")
    parser.add_argument("--frida_version", type=str)
    

    args = parser.parse_args()
    inputfile = args.input
    outputfile = args.output
    keyalias = args.keyalias
    storepass = args.storepass
    keystore = None
    frida_version = args.frida_version

    if not check_tools():
        exit(1)
    
    create_temp_folder()
    temp_apk = copy_apk_to_temp_folder(inputfile)

    archs = get_arch(temp_apk)
    if len(archs) == 0:
        print("Current ABI is not supported!")
        exit(1)
    
    if(args.keystore):
        keystore = args.keystore
    else:
        keystore = create_keystore(keyalias, storepass)

    unpack_apk(temp_apk)
    #inject_load_library("com.instagram.mainactivity.LauncherActivity")
    inject_load_library("com.instagram.service.tigon.configs.IGTigonConfig")

    config_file = create_config_file()
    print("Created config_file at: ", config_file)
    script = copy_script_temp()
    print("Created script_file at: ", script)
    for arch in archs:
        print("\nPatching for", arch)
        arch_folder = os.path.join(TEMP_FOLDER, "app", "lib", arch)
        download_frida_gadget(arch, frida_version)
        shutil.copy(config_file, arch_folder)
        shutil.copy(script, arch_folder)

    output = pack_apk()
    zip_align_apk(output)
    sign_apk(output, keystore, keyalias, storepass)
    outputpath = shutil.move(output, outputfile)
    delete_temp_folder()
    print("Sucessful. Patched file at:", outputpath)

main()
