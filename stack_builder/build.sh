#!/bin/sh
set -e

export TMPDIR="$PWD/tmp"
rm -rf "$TMPDIR"
mkdir -p "$TMPDIR"

out=out/Release
flags="
  is_official_build=false
  chrome_pgo_phase=0
  exclude_unwind_tables=true
  enable_resource_allowlist_generation=false
  symbol_level=0"

. ./get-sysroot.sh

# ccache
case "$host_os" in
  linux|mac)
    if which ccache >/dev/null 2>&1; then
      export CCACHE_SLOPPINESS=time_macros
      export CCACHE_BASEDIR="$PWD"
      export CCACHE_CPP2=yes
      CCACHE=ccache
    fi
  ;;
  win)
    if [ -f "$HOME"/.cargo/bin/sccache* ]; then
      export PATH="$PATH:$HOME/.cargo/bin"
      CCACHE=sccache
    fi
  ;;
esac
if [ "$CCACHE" ]; then
  flags="$flags
    cc_wrapper=\"$CCACHE\""
fi

# Основные безопасные флаги
#  use_udev=false
#  use_aura=false
#  use_ozone=false
#  use_gio=false
#  use_glib=false
#   use_cups=false
#  use_sysroot=false
#  use_nss_certs=false

flags="$flags"'
  is_clang=true
  fatal_linker_warnings=false
  treat_warnings_as_errors=false
  is_perfetto_embedder=true
  enable_websockets=false
  use_kerberos=false
  enable_mdns=false
  enable_reporting=false
  include_transport_security_state_preload_list=false
  enable_device_bound_sessions=false
  enable_disk_cache_sql_backend=false
  enable_backup_ref_ptr_support=false
  enable_dangling_raw_ptr_checks=false
  use_clang_modules=false
  is_component_build=false
'

# ПРАВИЛЬНОЕ ОПРЕДЕЛЕНИЕ ANDROID И ИЗОЛЯЦИЯ ФЛАГОВ CRONET/ICU
IS_ANDROID=false
case "$EXTRA_FLAGS" in
  *target_os=\"android\"*) IS_ANDROID=true ;;
esac
if [ "$target_os" = "android" ]; then IS_ANDROID=true; fi

if [ "$IS_ANDROID" = "true" ]; then
  echo "=> Configuring for Android (Cronet mode)"
  flags="$flags"'
    is_cronet_build=true
    use_platform_icu_alternatives=true
    is_desktop_android=true
    use_nss_certs=false
    default_min_sdk_version=27'

  # is_high_end_android ломает сборку 32-битных архитектур в Chromium v152+
  if echo "$EXTRA_FLAGS" | grep -q 'target_cpu="x64"\|target_cpu="arm64"'; then
    flags="$flags"'
    is_high_end_android=true'
  fi
else
  echo "=> Configuring for Desktop (Native mode)"
  flags="$flags"'
    is_cronet_build=false
    use_platform_icu_alternatives=false
    use_cups=false'
fi

if [ "$WITH_SYSROOT" ]; then
  flags="$flags
    use_sysroot=true
    target_sysroot=\"//$WITH_SYSROOT\""
else
  flags="$flags
    use_sysroot=false"
fi

if [ "$host_os" = "mac" ]; then
  flags="$flags"'
    use_system_xcode=true
    mac_allow_system_xcode_for_official_builds_for_testing=true
    enable_dsyms=false'
fi

if [ "$target_os" = "linux" -a "$target_cpu" = "x64" ]; then
  flags="$flags"'
    use_cfi_icall=false'
fi

# ФЕЙКУЕМ gclient_args (Нужно для GN-разрешения JNI зависимостей на Android)
mkdir -p build/config
echo "" >> build/config/gclient_args.gni
echo 'checkout_android = true' >> build/config/gclient_args.gni
echo 'checkout_android_native_support = true' >> build/config/gclient_args.gni

# Накатываем патчи Eidolon
echo "Applying Eidolon Patches..."
python3 patch_chromium_v152.py || true

if [ "$host_os" = mac ]; then
  echo "Applying macOS SDK modulemap fix..."
  # Удаляем любые строки, где упоминается DarwinFoundation 1, 2 или 3
  sed -i '' -E '/DarwinFoundation[1-3]\.modulemap/d' build/modules/BUILD.gn || true
fi

# СОЗДАЕМ ИЗОЛИРОВАННЫЙ ТАРГЕТ ДЛЯ EIDOLON
mkdir -p net/eidolon
cp eidolon_bridge.cc net/eidolon/
cp eidolon_bridge.h net/eidolon/

cat << 'EOF' > net/eidolon/BUILD.gn
shared_library("libeidolon") {
  sources = [ "eidolon_bridge.cc" ]
  deps = [
    "//net:net",
    "//base:base",
    "//url:url",
    "//crypto:crypto",
    "//third_party/boringssl:boringssl",
  ]
}
EOF

# ПРИВЯЗЫВАЕМ ТАРГЕТ К КОРНЮ, ЧТОБЫ GN ЕГО УВИДЕЛ
echo 'group("eidolon") { deps = [ "//net/eidolon:libeidolon" ] }' >> BUILD.gn

rm -rf "./$out"
mkdir -p out

export DEPOT_TOOLS_WIN_TOOLCHAIN=0

# Восстановление утилиты форматирования для Windows-окружения
if [ "$host_os" = "win" ]; then
  if [ ! -f buildtools/win-format/clang-format.exe ]; then
    echo "Copying clang-format for Windows from LLVM toolchain..."
    mkdir -p buildtools/win-format
    # Берем готовый бинарник, который Chromium уже скачал для компилятора
    if [ -f third_party/llvm-build/Release+Asserts/bin/clang-format.exe ]; then
      cp third_party/llvm-build/Release+Asserts/bin/clang-format.exe buildtools/win-format/clang-format.exe
    fi
  fi
fi

echo "Running GN..."
./gn/out/gn gen "$out" --args="$flags $EXTRA_FLAGS"

if [ "$host_os" = linux ]; then
  clang_x64_targets=$(grep -o ' | .*' $out/toolchain.ninja | grep -o ' clang_x64/[^ ]*' | sort -u || true)
  if [ "$clang_x64_targets" ]; then
    echo "Building host tools..."
    CCACHE_DIR=$PWD/.host_tool_cache ninja -C "$out" $clang_x64_targets
  fi
fi

echo "Building libeidolon..."
ninja -C "$out" eidolon

echo "Stripping binaries..."
if [ "$host_os" = "linux" ]; then
  strip "$out"/libeidolon.so || true
elif [ "$host_os" = "mac" ]; then
  strip -x "$out"/libeidolon.dylib "$out"/libeidolon.so 2>/dev/null || true
elif [ "$host_os" = "win" ]; then
  echo "Stripping on Windows is handled by linking flags."
fi