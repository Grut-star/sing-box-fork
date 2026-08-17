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

flags="$flags"'
  is_clang=true
  use_sysroot=false

  fatal_linker_warnings=false
  treat_warnings_as_errors=false

  is_cronet_build=true

  use_udev=false
  use_aura=false
  use_ozone=false
  use_gio=false
  use_platform_icu_alternatives=true
  use_glib=false
  is_perfetto_embedder=true

  disable_file_support=true
  enable_websockets=false
  use_kerberos=false
  disable_zstd_filter=false
  enable_mdns=false
  enable_reporting=false
  include_transport_security_state_preload_list=false
  enable_device_bound_sessions=false
  enable_disk_cache_sql_backend=false

  use_nss_certs=false

  enable_backup_ref_ptr_support=false
  enable_dangling_raw_ptr_checks=false

  use_clang_modules=false
  is_component_build=false
'

if [ "$WITH_SYSROOT" ]; then
  flags="$flags
    target_sysroot=\"//$WITH_SYSROOT\""
fi

if [ "$host_os" = "mac" ]; then
  flags="$flags"'
    mac_allow_system_xcode_for_official_builds_for_testing=true
    enable_dsyms=false'
fi

case "$EXTRA_FLAGS" in
*target_os=\"android\"*)
  flags="$flags"'
    is_desktop_android=true
    default_min_sdk_version=27
    is_high_end_android=true'
  ;;
esac

if [ "$target_os" = "linux" -a "$target_cpu" = "x64" ]; then
  flags="$flags"'
    use_cfi_icall=false'
fi

# ФЕЙКУЕМ gclient_args
mkdir -p build/config
echo "" >> build/config/gclient_args.gni
echo 'checkout_android = true' >> build/config/gclient_args.gni
echo 'checkout_android_native_support = true' >> build/config/gclient_args.gni

# Накатываем патчи Eidolon (файлы теперь лежат в этой же директории src/)
echo "Applying Eidolon Patches..."
python3 patch_chromium_v152.py || true
cp eidolon_bridge.cc net/socket/
cp eidolon_bridge.h net/socket/

# Добавляем GN-таргет
if ! grep -q 'shared_library("libeidolon")' net/BUILD.gn; then
cat << 'EOF' >> net/BUILD.gn

shared_library("libeidolon") {
  sources = [ "socket/eidolon_bridge.cc" ]
  deps = [
    "//net:net",
    "//base:base",
    "//url:url",
    "//crypto:crypto",
    "//third_party/boringssl:boringssl",
  ]
}
EOF
fi

rm -rf "./$out"
mkdir -p out

export DEPOT_TOOLS_WIN_TOOLCHAIN=0

./gn/out/gn gen "$out" --args="$flags $EXTRA_FLAGS"

if [ "$host_os" = linux ]; then
  clang_x64_targets=$(grep -o ' | .*' $out/toolchain.ninja | grep -o ' clang_x64/[^ ]*' | sort -u || true)
  if [ "$clang_x64_targets" ]; then
    echo "Building host tools..."
    CCACHE_DIR=$PWD/.host_tool_cache ninja -C "$out" $clang_x64_targets
  fi
fi

echo "Building libeidolon..."
ninja -C "$out" net:libeidolon