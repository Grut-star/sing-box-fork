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
  # Пере-скачиваем NDK не только когда каталога нет, но и когда в нём отсутствуют
  # compiler-rt builtins. Это чинит СТАРЫЙ кэш GitHub, запруненный прежней версией
  # этого скрипта (там builtins уже вырезаны, а ветку скачивания cache-hit
  # пропускал — из-за чего SOLINK и падал даже после правки keep-списка).
  if [ ! -d third_party/android_toolchain/ndk ] || \
     ! find third_party/android_toolchain/ndk -type f -name 'libclang_rt.builtins*' 2>/dev/null | grep -q .; then
    echo "NDK missing or has no compiler-rt builtins -> (re)downloading..."
    rm -rf third_party/android_toolchain/ndk
    android_ndk_version=r24
    curl -LO https://dl.google.com/android/repository/android-ndk-$android_ndk_version-linux.zip
    unzip -q android-ndk-$android_ndk_version-linux.zip
    mkdir -p third_party/android_toolchain/ndk
    cd android-ndk-$android_ndk_version
    cp -r --parents sources/android/cpufeatures ../third_party/android_toolchain/ndk
    cp -r --parents toolchains/llvm/prebuilt ../third_party/android_toolchain/ndk
    cd ..
    cd third_party/android_toolchain/ndk
    # ВАЖНО: libclang_rt[^/]*\.a обязан быть в keep-списке — это compiler-rt
    # builtins (libclang_rt.builtins-<arch>-android.a), которые линкер lld требует
    # при сборке .so под Android. Без него прунинг вырезал их из NDK, и SOLINK
    # падал с "cannot open .../<triple><api>/libclang_rt.builtins.a".
    find toolchains -type f -regextype egrep \! -regex \
      '.*(lib(atomic|gcc|gcc_real|compiler_rt-extras|android_support|unwind).a|libclang_rt[^/]*\.a|crt.*o|lib(android|c|dl|log|m).so|usr/local.*|usr/include.*)' -delete
    sed -i 's/AHARDWAREBUFFER_USAGE_FRONT_BUFFER = 1UL /AHARDWAREBUFFER_USAGE_FRONT_BUFFER = 1ULL /' toolchains/llvm/prebuilt/linux-x86_64/sysroot/usr/include/android/hardware_buffer.h
    cd -
    rm -rf android-ndk-$android_ndk_version android-ndk-$android_ndk_version-linux.zip
  fi

  # ===========================================================================
  # ФИКС - ВЫНЕСЕН ЗА ПРЕДЕЛЫ NDK DOWNLOAD, ЧТОБЫ ЛЕЧИТЬ СТАРЫЙ КЭШ GITHUB
  # ===========================================================================
  echo "Patching Android NDK libraries (ensuring cached NDK is also fixed)..."
  cd third_party/android_toolchain/ndk
  CLANG_LIB_DIR=$(find toolchains/llvm/prebuilt/linux-x86_64/lib/clang -type d -name "linux" | head -n 1)
  if [ -n "$CLANG_LIB_DIR" ]; then
    # aarch64
    mkdir -p toolchains/llvm/prebuilt/linux-x86_64/sysroot/usr/lib/aarch64-linux-android/27
    cp "$CLANG_LIB_DIR/aarch64/libatomic.a" toolchains/llvm/prebuilt/linux-x86_64/sysroot/usr/lib/aarch64-linux-android/27/ 2>/dev/null || true
    cp "$CLANG_LIB_DIR/aarch64/libunwind.a" toolchains/llvm/prebuilt/linux-x86_64/sysroot/usr/lib/aarch64-linux-android/27/ 2>/dev/null || true

    # arm (32-bit)
    mkdir -p toolchains/llvm/prebuilt/linux-x86_64/sysroot/usr/lib/arm-linux-androideabi/27
    cp "$CLANG_LIB_DIR/arm/libatomic.a" toolchains/llvm/prebuilt/linux-x86_64/sysroot/usr/lib/arm-linux-androideabi/27/ 2>/dev/null || true
    cp "$CLANG_LIB_DIR/arm/libunwind.a" toolchains/llvm/prebuilt/linux-x86_64/sysroot/usr/lib/arm-linux-androideabi/27/ 2>/dev/null || true

    # i686 (x86 32-bit)
    mkdir -p toolchains/llvm/prebuilt/linux-x86_64/sysroot/usr/lib/i686-linux-android/27
    cp "$CLANG_LIB_DIR/i386/libatomic.a" toolchains/llvm/prebuilt/linux-x86_64/sysroot/usr/lib/i686-linux-android/27/ 2>/dev/null || true
    cp "$CLANG_LIB_DIR/i386/libunwind.a" toolchains/llvm/prebuilt/linux-x86_64/sysroot/usr/lib/i686-linux-android/27/ 2>/dev/null || true

    # x86_64
    mkdir -p toolchains/llvm/prebuilt/linux-x86_64/sysroot/usr/lib/x86_64-linux-android/27
    cp "$CLANG_LIB_DIR/x86_64/libatomic.a" toolchains/llvm/prebuilt/linux-x86_64/sysroot/usr/lib/x86_64-linux-android/27/ 2>/dev/null || true
    cp "$CLANG_LIB_DIR/x86_64/libunwind.a" toolchains/llvm/prebuilt/linux-x86_64/sysroot/usr/lib/x86_64-linux-android/27/ 2>/dev/null || true
  fi
  cd -
  # ===========================================================================

#  echo "Injecting System JDK via wrapper scripts..."
#  rm -rf third_party/jdk/current
#  mkdir -p third_party/jdk/current/bin
#  for tool in java javac javap jar; do
#    TOOL_PATH=$(which $tool || true)
#    if [ -n "$TOOL_PATH" ]; then
#      cat << EOF > "third_party/jdk/current/bin/$tool"
##!/bin/sh
#exec "$TOOL_PATH" "\$@"
#EOF
#      chmod +x "third_party/jdk/current/bin/$tool"
#    fi
#  done
#
#  if [ ! -f third_party/android_sdk/public/platforms/android-37.0/android.jar ]; then
#    echo "Setting up Android SDK mock..."
#    mkdir -p third_party/android_sdk/public/platforms/android-37.0
#    if [ -n "$ANDROID_HOME" ] && [ -d "$ANDROID_HOME/platforms" ]; then
#      LATEST_API=$(ls -1 "$ANDROID_HOME/platforms" 2>/dev/null | grep -E '^android-[0-9]+$' | sort -V | tail -n 1)
#      if [ -n "$LATEST_API" ]; then
#        cp "$ANDROID_HOME/platforms/$LATEST_API/android.jar" third_party/android_sdk/public/platforms/android-37.0/android.jar || true
#      fi
#    fi
#    if [ ! -f third_party/android_sdk/public/platforms/android-37.0/android.jar ]; then
#      curl -L -o third_party/android_sdk/public/platforms/android-37.0/android.jar "https://github.com/Sable/android-platforms/raw/master/android-28/android.jar"
#    fi
#  fi
  echo "Fetching genuine Android Java Toolchain via CIPD..."
  curl -L -s "https://chrome-infra-packages.appspot.com/client?platform=linux-amd64&version=latest" -o cipd
  chmod +x cipd

  cat << 'EOF' > parse_deps.py
exec_locals = {}
def Var(name): return exec_locals.get('vars', {}).get(name, str(name))

with open("DEPS") as f:
    try:
        exec(f.read(), {'Var': Var, 'Str': str}, exec_locals)
    except Exception: pass

ensure = []
deps = {}
deps.update(exec_locals.get('deps', {}))
deps.update(exec_locals.get('deps_os', {}).get('android', {}))

# УЛЬТИМАТИВНЫЙ ФИЛЬТР: Включены все критичные узлы Java-компилятора
allowed_keywords = ['android', 'r8', 'jdk', 'androidx', 'kotlin', 'jni', 'proto', 'turbine', 'dagger', 'guava', 'errorprone', 'auto', 'netty', 'bouncycastle', 'robolectric', 'sqlite', 'objenesis', 'byte_buddy']

for path, dep in deps.items():
    if isinstance(dep, dict) and 'packages' in dep:
        if not any(k in path.lower() for k in allowed_keywords):
            continue
        # android_toolchain/ndk ставится ВРУЧНУЮ выше (r24 + сохранение
        # compiler-rt builtins). Не даём cipd затереть его пакетом android_toolchain,
        # иначе builtins снова пропадут и SOLINK упадёт.
        if 'android_toolchain' in path:
            continue

        for pkg in dep['packages']:
            p = str(pkg.get('package', ''))
            v = str(pkg.get('version', ''))

            if not p or not v: continue

            # Раскрываем плейсхолдеры ДО проверки на остаток шаблона. DEPS
            # использует двойные скобки ${{platform}} (gclient-шаблон), поэтому
            # обрабатываем и ${{x}}, и ${x}, и {x}. Раньше отсев '$'/'{' стоял
            # до замены — и ВСЕ платформенные CIPD-пакеты (protoc и прочие
            # нативные бинари android_build_tools) выбрасывались, из-за чего
            # ninja падал на отсутствующем .../protoc/cipd/protoc.
            for ph, val in (('platform', 'linux-amd64'), ('os', 'linux'), ('arch', 'amd64')):
                for tok in ('${{%s}}' % ph, '${%s}' % ph, '{%s}' % ph):
                    p = p.replace(tok, val)
                    v = v.replace(tok, val)

            # Остался нераскрытый шаблон — резолвить не умеем, пропускаем.
            if '{' in p or '$' in p or '{' in v or '$' in v: continue

            ensure.append(f"@Subdir {path.replace('src/', '')}")
            ensure.append(f"{p} {v}")

with open("cipd_android.txt", "w") as f: f.write("\n".join(ensure))
EOF

  python3 parse_deps.py
  ./cipd ensure -root . -ensure-file cipd_android.txt
  rm cipd parse_deps.py cipd_android.txt
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