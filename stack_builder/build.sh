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

  if echo "$EXTRA_FLAGS" | grep -q 'target_cpu="x64"\|target_cpu="arm64"'; then
    flags="$flags"'
    is_high_end_android=true'
  fi
else
  echo "=> Configuring for Desktop (Native mode)"
  flags="$flags"'
    is_cronet_build=false
    use_platform_icu_alternatives=false'
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

mkdir -p build/config
echo "" >> build/config/gclient_args.gni
echo 'checkout_android = true' >> build/config/gclient_args.gni
echo 'checkout_android_native_support = true' >> build/config/gclient_args.gni

echo "Applying Eidolon Patches..."
python3 patch_chromium_v152.py || true

if [ "$host_os" = mac ]; then
  sed -i '' -E '/DarwinFoundation[1-3]\.modulemap/d' build/modules/BUILD.gn || true
fi

mkdir -p tools/metrics
if [ ! -f tools/metrics/BUILD.gn ]; then
  echo 'group("histograms_xml") {}' > tools/metrics/BUILD.gn
else
  echo 'group("histograms_xml") {}' >> tools/metrics/BUILD.gn
fi

# 1. Подготавливаем исходники C++ (возвращаем рабочий вариант)
mkdir -p net/eidolon
cp eidolon_bridge.cc net/eidolon/
cp eidolon_bridge.h net/eidolon/

# 2. Подготавливаем CGO-мост, который требует bridge.h
# Поднимаемся на папку выше и заходим в protocol
cp ../protocol/eidolon/bridge.h net/eidolon/

cat << 'EOF' > net/eidolon/BUILD.gn
shared_library("libeidolon") {
  sources = [ "eidolon_bridge.cc" ]
  deps = [
    "//net:net",
    "//base:base",
    "//url:url",
    "//crypto:crypto",
    "//third_party/boringssl:boringssl",
    "//components/version_info",
    "//net/third_party/quiche:quiche_tool_support",
  ]
}
EOF

echo 'group("eidolon") { deps = [ "//net/eidolon:libeidolon" ] }' >> BUILD.gn

rm -rf "./$out"
mkdir -p out

export DEPOT_TOOLS_WIN_TOOLCHAIN=0

if [ "$host_os" = "win" ]; then
  if [ ! -f buildtools/win-format/clang-format.exe ]; then
    mkdir -p buildtools/win-format
    if [ -f third_party/llvm-build/Release+Asserts/bin/clang-format.exe ]; then
      cp third_party/llvm-build/Release+Asserts/bin/clang-format.exe buildtools/win-format/clang-format.exe || true
    else
      curl -sL "https://github.com/angular/clang-format/raw/master/bin/win32/clang-format.exe" -o buildtools/win-format/clang-format.exe
    fi
  fi
fi

echo "=== DIAGNOSTICS: WHO IS REQUIRING ATOMIC IN GN? ==="
grep -rn '"atomic"' build/config/ || true
echo "==================================================="

echo "Patching Chromium's bundled Python to use system Python..."
rm -rf third_party/cpython3/host/bin/python3* third_party/cpython3/host/bin/python.exe*
mkdir -p third_party/cpython3/host/bin

if [ "$host_os" = "win" ]; then
  SYS_PYTHON=$(which python3 2>/dev/null || which python)
  cp "$SYS_PYTHON" third_party/cpython3/host/bin/python3.exe
else
  ln -sf "$(which python3)" third_party/cpython3/host/bin/python3
fi

if [ "$host_os" = "win" ]; then
  echo "Hotfixing broken Windows SDK 10.0.28000.0..."
  python3 -c "
import os
files = ['build/toolchain/win/setup_toolchain.py', 'build/vs_toolchain.py']
for filepath in files:
    if os.path.exists(filepath):
        with open(filepath, 'r', encoding='utf-8') as f:
            content = f.read()
        # Жесткая подмена версии SDK до начала работы парсеров
        content = content.replace('10.0.28000.0', '10.0.22621.0')
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(content)
"
fi

echo "Running GN..."
./gn/out/gn gen "$out" --args="$flags $EXTRA_FLAGS"

echo "=== DIAGNOSTICS: CHECKING NINJA FILES FOR -latomic ==="
grep -rn "latomic" "$out"/ || true
echo "======================================================"

if [ "$host_os" = linux ]; then
  clang_x64_targets=$(grep -o ' | .*' $out/toolchain.ninja | grep -o ' clang_x64/[^ ]*' | sort -u || true)
  if [ "$clang_x64_targets" ]; then
    CCACHE_DIR=$PWD/.host_tool_cache ninja -C "$out" $clang_x64_targets
  fi
fi

echo "Building libeidolon (VERBOSE)..."
if ! ninja -v -C "$out" eidolon; then
  echo "=== DIAGNOSTICS: LINKER FAILED! DUMPING SYSROOT CONTENTS ==="
  ls -laR third_party/android_toolchain/ndk/toolchains/llvm/prebuilt/linux-x86_64/sysroot/usr/lib/ || true
  ls -laR third_party/android_toolchain/ndk/toolchains/llvm/prebuilt/linux-x86_64/lib64/clang/ || true
  echo "============================================================"
  exit 1
fi

echo "Stripping binaries..."
STRIP_TOOL="third_party/llvm-build/Release+Asserts/bin/llvm-strip"
if [ "$host_os" = "win" ]; then
  STRIP_TOOL="${STRIP_TOOL}.exe"
fi

if [ -x "$STRIP_TOOL" ]; then
  echo "Using llvm-strip..."
  if [ "$host_os" = "win" ]; then
    "$STRIP_TOOL" --strip-unneeded "$out"/*eidolon*.dll 2>/dev/null || true
  elif [ "$host_os" = "mac" ]; then
    "$STRIP_TOOL" -x "$out"/libeidolon.dylib "$out"/libeidolon.so 2>/dev/null || true
  else
    "$STRIP_TOOL" --strip-unneeded "$out"/libeidolon.so 2>/dev/null || true
  fi
else
  echo "llvm-strip not found, skipping."
fi