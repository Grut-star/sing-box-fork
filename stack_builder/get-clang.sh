#!/bin/sh
set -ex

. ./get-sysroot.sh

if [ "$SYSROOT_ARCH" -a ! -d ./"$WITH_SYSROOT/lib" ]; then
  ./build/linux/sysroot_scripts/sysroot_creator.py build "$SYSROOT_ARCH" || true
fi

if [ "$OPENWRT_FLAGS" ]; then
  ./get-openwrt.sh
fi

# Загружаем DEPS и update.py напрямую, если их нет (нужно для Cache-джобов без полного исходника)
if [ ! -f DEPS ]; then
  curl -s "https://raw.githubusercontent.com/chromium/chromium/${CHROMIUM_VERSION}/DEPS" -o DEPS
fi
if [ ! -f tools/clang/scripts/update.py ]; then
  mkdir -p tools/clang/scripts
  curl -s "https://raw.githubusercontent.com/chromium/chromium/${CHROMIUM_VERSION}/tools/clang/scripts/update.py" -o tools/clang/scripts/update.py
fi

# Clang
echo "Fetching Clang toolchain..."
$PYTHON tools/clang/scripts/update.py

# Скачиваем предкомпилированный Rust и bindgen (решает проблемы с GN)
echo "Fetching Rust toolchain..."
if [ -f tools/rust/update_rust.py ]; then
  $PYTHON tools/rust/update_rust.py
fi
# ----------------------------

# sccache
if [ "$host_os" = win -a ! -f ~/.cargo/bin/sccache.exe ]; then
  sccache_url="https://github.com/mozilla/sccache/releases/download/0.2.12/sccache-0.2.12-x86_64-pc-windows-msvc.tar.gz"
  mkdir -p ~/.cargo/bin
  curl -L "$sccache_url" | tar xzf - --strip=1 -C ~/.cargo/bin
fi

# Windows Clang-Format Fetch
if [ "$host_os" = win -a ! -f buildtools/win-format/clang-format.exe ]; then
  echo "Fetching clang-format for Windows..."
  mkdir -p buildtools/win-format
  if [ -f buildtools/win-format/clang-format.exe.sha1 ]; then
    FORMAT_SHA=$(cat buildtools/win-format/clang-format.exe.sha1)
    curl -L "https://storage.googleapis.com/chromium-clang-format/$FORMAT_SHA" -o buildtools/win-format/clang-format.exe
  fi
fi

# GN
case "$host_os" in
  linux) WITH_GN=linux-amd64;;
  win) WITH_GN=windows-amd64;;
  mac) WITH_GN=mac-amd64;;
esac
if [ "$host_os" = mac -a "$host_cpu" = arm64 ]; then
  WITH_GN=mac-arm64
fi
if [ ! -f gn/out/gn ]; then
  gn_version=$(grep "'gn_version':" DEPS | cut -d"'" -f4)
  mkdir -p gn/out
  curl -L "https://chrome-infra-packages.appspot.com/dl/gn/gn/$WITH_GN/+/$gn_version" -o gn.zip
  unzip -q gn.zip -d gn/out
  rm gn.zip
fi

# Android NDK / SDK / JDK / libunwindstack (Специфика Eidolon / Chromium Android)
if [ "$target_os" = android ]; then
  if [ ! -d third_party/android_toolchain/ndk ]; then
    android_ndk_version=r24
    curl -LO https://dl.google.com/android/repository/android-ndk-$android_ndk_version-linux.zip
    unzip -q android-ndk-$android_ndk_version-linux.zip
    mkdir -p third_party/android_toolchain/ndk
    cd android-ndk-$android_ndk_version
    cp -r --parents sources/android/cpufeatures ../third_party/android_toolchain/ndk
    cp -r --parents toolchains/llvm/prebuilt ../third_party/android_toolchain/ndk
    cd ..
    cd third_party/android_toolchain/ndk
    find toolchains -type f -regextype egrep \! -regex \
      '.*(lib(atomic|gcc|gcc_real|compiler_rt-extras|android_support|unwind).a|crt.*o|lib(android|c|dl|log|m).so|usr/local.*|usr/include.*)' -delete
    sed -i 's/AHARDWAREBUFFER_USAGE_FRONT_BUFFER = 1UL /AHARDWAREBUFFER_USAGE_FRONT_BUFFER = 1ULL /' toolchains/llvm/prebuilt/linux-x86_64/sysroot/usr/include/android/hardware_buffer.h
    mkdir -p toolchains/llvm/prebuilt/linux-x86_64/sysroot/usr/lib/aarch64-linux-android/27/
    find toolchains/llvm/prebuilt/linux-x86_64/lib64/clang -type f -name "*.a" | grep aarch64 | xargs -I {} cp {} toolchains/llvm/prebuilt/linux-x86_64/sysroot/usr/lib/aarch64-linux-android/27/
    cd -
    rm -rf android-ndk-$android_ndk_version android-ndk-$android_ndk_version-linux.zip
  fi

  # JDK Mock
  if [ -n "$JAVA_HOME" ]; then
    echo "Injecting System JDK via hard copy..."
    rm -rf third_party/jdk/current
    mkdir -p third_party/jdk/current/bin

    # Копируем бинарники с принудительным разрешением симлинков (-L)
    for tool in java javac javap jar; do
      TOOL_PATH=$(which $tool || true)
      if [ -n "$TOOL_PATH" ]; then
        cp -L "$TOOL_PATH" "third_party/jdk/current/bin/$tool"
      fi
    done

    # Линкуем библиотеки
    ln -sfn "$JAVA_HOME/lib" third_party/jdk/current/lib || true
    ln -sfn "$JAVA_HOME/include" third_party/jdk/current/include || true
  fi

  # SDK Mock
  if [ ! -f third_party/android_sdk/public/platforms/android-37.0/android.jar ]; then
    mkdir -p third_party/android_sdk/public/platforms/android-37.0
    if [ -n "$ANDROID_HOME" ]; then
      # Ищем самый свежий android.jar в системе
      JAR_PATH=$(find "$ANDROID_HOME/platforms" -name "android.jar" | sort -V | tail -n 1)
      if [ -n "$JAR_PATH" ]; then
        cp "$JAR_PATH" third_party/android_sdk/public/platforms/android-37.0/android.jar
      else
        touch third_party/android_sdk/public/platforms/android-37.0/android.jar
      fi
    else
      touch third_party/android_sdk/public/platforms/android-37.0/android.jar
    fi
  fi
fi

# libunwindstack fetch (Если его нет в исходниках)
if [ ! -d third_party/libunwindstack/.git ]; then
  UNWIND_HASH=$(grep -A 3 "'src/third_party/libunwindstack':" DEPS | grep 'url' | grep -oE '[a-f0-9]{40}' || echo "main")
  mkdir -p third_party/libunwindstack
  cd third_party/libunwindstack
  git init
  git remote add origin https://chromium.googlesource.com/chromium/src/third_party/libunwindstack.git || true
  git fetch --depth 1 origin $UNWIND_HASH
  git checkout FETCH_HEAD
  cd ../..
fi