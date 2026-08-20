#!/bin/sh
set -ex

. ./get-sysroot.sh

if [ "$SYSROOT_ARCH" -a ! -d ./"$WITH_SYSROOT/lib" ]; then
  ./build/linux/sysroot_scripts/sysroot_creator.py build "$SYSROOT_ARCH" || true
fi

if [ "$OPENWRT_FLAGS" ]; then
  ./get-openwrt.sh
fi

if [ ! -f DEPS ]; then
  curl -s "https://raw.githubusercontent.com/chromium/chromium/${CHROMIUM_VERSION}/DEPS" -o DEPS
fi
if [ ! -f tools/clang/scripts/update.py ]; then
  mkdir -p tools/clang/scripts
  curl -s "https://raw.githubusercontent.com/chromium/chromium/${CHROMIUM_VERSION}/tools/clang/scripts/update.py" -o tools/clang/scripts/update.py
fi

echo "Fetching Clang toolchain..."
$PYTHON tools/clang/scripts/update.py

if [ "$host_os" = "win" ]; then
  echo "Copying clang-format for Windows..."
  mkdir -p buildtools/win-format
  cp third_party/llvm-build/Release+Asserts/bin/clang-format.exe buildtools/win-format/clang-format.exe || true
fi

if [ "$host_os" = "mac" ]; then
  echo "Symlinking system tools for macOS..."
  mkdir -p third_party/llvm-build/Release+Asserts/bin
  for tool in otool install-name-tool nm strip; do
    if [ ! -f "third_party/llvm-build/Release+Asserts/bin/llvm-$tool" ]; then
      cat << EOF > "third_party/llvm-build/Release+Asserts/bin/llvm-$tool"
#!/bin/sh
exec /usr/bin/$tool "\$@"
EOF
      chmod +x "third_party/llvm-build/Release+Asserts/bin/llvm-$tool"
    fi
  done
fi

echo "Fetching Rust toolchain..."
if [ -f tools/rust/update_rust.py ]; then
  $PYTHON tools/rust/update_rust.py
fi

if [ "$host_os" = win -a ! -f ~/.cargo/bin/sccache.exe ]; then
  sccache_url="https://github.com/mozilla/sccache/releases/download/0.2.12/sccache-0.2.12-x86_64-pc-windows-msvc.tar.gz"
  mkdir -p ~/.cargo/bin
  curl -L "$sccache_url" | tar xzf - --strip=1 -C ~/.cargo/bin
fi

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

    # Мы больше НЕ УДАЛЯЕМ ничего из NDK, чтобы не повредить пути линкера
    sed -i 's/AHARDWAREBUFFER_USAGE_FRONT_BUFFER = 1UL /AHARDWAREBUFFER_USAGE_FRONT_BUFFER = 1ULL /' third_party/android_toolchain/ndk/toolchains/llvm/prebuilt/linux-x86_64/sysroot/usr/include/android/hardware_buffer.h

    echo "Distributing clang builtins to sysroot..."
    CLANG_LIB_DIR=$(find third_party/android_toolchain/ndk/toolchains/llvm/prebuilt/linux-x86_64/lib64/clang -type d -name "linux" | head -n 1)
    if [ -n "$CLANG_LIB_DIR" ]; then
      mkdir -p third_party/android_toolchain/ndk/toolchains/llvm/prebuilt/linux-x86_64/sysroot/usr/lib/aarch64-linux-android/27
      cp "$CLANG_LIB_DIR"/*aarch64*.a third_party/android_toolchain/ndk/toolchains/llvm/prebuilt/linux-x86_64/sysroot/usr/lib/aarch64-linux-android/27/ 2>/dev/null || true

      mkdir -p third_party/android_toolchain/ndk/toolchains/llvm/prebuilt/linux-x86_64/sysroot/usr/lib/arm-linux-androideabi/27
      cp "$CLANG_LIB_DIR"/*arm*.a third_party/android_toolchain/ndk/toolchains/llvm/prebuilt/linux-x86_64/sysroot/usr/lib/arm-linux-androideabi/27/ 2>/dev/null || true

      mkdir -p third_party/android_toolchain/ndk/toolchains/llvm/prebuilt/linux-x86_64/sysroot/usr/lib/i686-linux-android/27
      cp "$CLANG_LIB_DIR"/*i686*.a third_party/android_toolchain/ndk/toolchains/llvm/prebuilt/linux-x86_64/sysroot/usr/lib/i686-linux-android/27/ 2>/dev/null || true

      mkdir -p third_party/android_toolchain/ndk/toolchains/llvm/prebuilt/linux-x86_64/sysroot/usr/lib/x86_64-linux-android/27
      cp "$CLANG_LIB_DIR"/*x86_64*.a third_party/android_toolchain/ndk/toolchains/llvm/prebuilt/linux-x86_64/sysroot/usr/lib/x86_64-linux-android/27/ 2>/dev/null || true
    fi

    echo "Compiling valid dummy libatomic.a to satisfy linker..."
    echo "void __dummy_atomic() {}" > dummy.c
    CLANG_BIN="third_party/llvm-build/Release+Asserts/bin/clang"
    AR_BIN="third_party/llvm-build/Release+Asserts/bin/llvm-ar"

    for target in arm-linux-androideabi aarch64-linux-android i686-linux-android x86_64-linux-android; do
      $CLANG_BIN -target ${target}27 -c dummy.c -o dummy_${target}.o || true
      $AR_BIN rcs libatomic_${target}.a dummy_${target}.o || true

      # Копируем свежесобранную валидную библиотеку во все возможные пути поиска линкера
      TARGET_DIR="third_party/android_toolchain/ndk/toolchains/llvm/prebuilt/linux-x86_64/sysroot/usr/lib/$target"
      mkdir -p "$TARGET_DIR/27"
      cp libatomic_${target}.a "$TARGET_DIR/27/libatomic.a" || true
      cp libatomic_${target}.a "$TARGET_DIR/libatomic.a" || true
      cp libatomic_${target}.a "$TARGET_DIR/27/libgcc.a" || true
    done
    rm -f dummy.c dummy_*.o libatomic_*.a

    rm -rf android-ndk-$android_ndk_version android-ndk-$android_ndk_version-linux.zip
  fi

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

  if [ ! -f third_party/android_sdk/public/platforms/android-37.0/android.jar ]; then
    echo "Setting up Android SDK mock..."
    mkdir -p third_party/android_sdk/public/platforms/android-37.0
    if [ -n "$ANDROID_HOME" ] && [ -d "$ANDROID_HOME/platforms" ]; then
      LATEST_API=$(ls -1 "$ANDROID_HOME/platforms" 2>/dev/null | grep -E '^android-[0-9]+$' | sort -V | tail -n 1)
      if [ -n "$LATEST_API" ]; then
        echo "Copying $LATEST_API android.jar from system..."
        cp "$ANDROID_HOME/platforms/$LATEST_API/android.jar" third_party/android_sdk/public/platforms/android-37.0/android.jar || true
      fi
    fi
    if [ ! -f third_party/android_sdk/public/platforms/android-37.0/android.jar ]; then
      echo "System android.jar not found! Downloading fallback..."
      curl -L -o third_party/android_sdk/public/platforms/android-37.0/android.jar "https://github.com/Sable/android-platforms/raw/master/android-28/android.jar"
    fi
  fi
fi

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