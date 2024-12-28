#!/bin/bash

# Used to create a new releases in github

[ -d output ] || mkdir output
rm -f output/*

app_version=

for file in ./apps/*.apk; do
    name=${file##*/}
    version_arch=$(echo $name | sed -nE 's/com.instagram.android_([^-]+)-.*\((arm64-v8a|armeabi-v7a|x86_64|x86)\).*/\1 \2/p')
    version=${version_arch% *}
    app_version=$version
    architecture=${version_arch#* }
    echo -e "\033[32mPatching: $version $architecture\033[0m"
    new_name=instagram-v$version-$architecture.apk
    python3 ./patch_apk.py -i $file --keystore ./release.keystore -o ./output/$new_name
done

old_version=$(sed -n '/instagram-v/{s/.*instagram-v\([^-]\+\).*/\1/;p;q}' ./README.md)
sed -i "s/v$old_version/v$app_version/g" ./README.md

git tag v$app_version

git add ./README.md
git commit -m "Update version to v$app_version"
git push origin --tags
gh release create v$app_version --notes "Patched Instagram v$app_version with SSL pinning bypassed." ./output/*.apk
git push
