#!/bin/sh
set -ex

. ./get-sysroot.sh

if [ "$SYSROOT_ARCH" -a ! -d ./"$WITH_SYSROOT/lib" ]; then
  ./build/linux/sysroot_scripts/sysroot_creator.py build "$SYSROOT_ARCH" || true
fi

if [ "$OPENWRT_FLAGS" ]; then
  ./get-openwrt.sh
fi

# Загружаем DEPS и update.py напрямую, если их нет
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

# Копируем clang-format для Windows (используем системный из runner'а или качаем резервный)
if [ "$host_os" = "win" ]; then
  echo "Setting up clang-format for Windows..."
  mkdir -p buildtools/win-format
  SYS_FORMAT=$(which clang-format || true)
  if [ -n "$SYS_FORMAT" ] && [ -f "$SYS_FORMAT" ]; then
    cp "$SYS_FORMAT" buildtools/win-format/clang-format.exe
  else
    # Надежный fallback - загрузка готового стабильного бинарника
    curl -sL "https://github.com/angular/clang-format/raw/master/bin/win32/clang-format.exe" -o buildtools/win-format/clang-format.exe
  fi
fi

# Подменяем недостающие утилиты LLVM bash-обертками на Mac
if [ "$host_os" = "mac" ]; then
  echo "Creating wrapper scripts for macOS system tools..."
  mkdir -p third_party/llvm-build/Release+Asserts/bin

  cat << 'EOF' > third_party/llvm-build/Release+Asserts/bin/llvm-otool
#!/bin/sh
exec /usr/bin/otool "$@"
EOF
  chmod +x third_party/llvm-build/Release+Asserts/bin/llvm-otool

  cat << 'EOF' > third_party/llvm-build/Release+Asserts/bin/llvm-install-name-tool
#!/bin/sh
exec /usr/bin/install-name-tool "$@"
EOF
  chmod +x third_party/llvm-build/Release+Asserts/bin/llvm-install-name-tool
fi

# Скачиваем предкомпилированный Rust
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

# Android NDK / SDK / JDK
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

  # JDK Mock (Умные bash-обертки)
  echo "Injecting System JDK via wrapper scripts..."
  rm -rf third_party/jdk/current
  mkdir -p third_party/jdk/current/bin
  for tool in java javac javap jar; do
    TOOL_PATH=$(which $tool || true)
    if [ -n "$TOOL_PATH" ]; then
      cat << EOF > "third_party/jdk/current/bin/$tool"
#!/bin/sh
exec "$TOOL_PATH" "\$@"
EOF
      chmod +x "third_party/jdk/current/bin/$tool"
    fi
  done

  # SDK Mock
  if [ ! -f third_party/android_sdk/public/platforms/android-37.0/android.jar ]; then
    mkdir -p third_party/android_sdk/public/platforms/android-37.0
    if [ -n "$ANDROID_HOME" ]; then
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

# libunwindstack fetch
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