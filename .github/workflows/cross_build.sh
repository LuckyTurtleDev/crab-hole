#!/usr/bin/env bash
set -exuo pipefail

envs=("RUST_BACKTRACE=1" "CARGO_PROFILE_RELEASE_LTO=true")

# prepare libc include dir
include=
if [ -n "$TARGET_INCLUDE" ]; then
	include="-isystem $TARGET_INCLUDE"
	envs+=("AWS_LC_SYS_INCLUDES=$TARGET_INCLUDE")
fi

# prepare sysroot flags, including linker search path
sysroot=
sysrootlinkarg=
if [ -n "$TARGET_SYSROOT" ]; then
	lsd -lh --tree "$TARGET_SYSROOT"
	# add normal sysroot flag
	sysroot="--sysroot $TARGET_SYSROOT"
	sysrootlinkarg="-C link-arg=--sysroot=${{matrix.target.sysroot}}"
	# clang/mold ain't smart enough to search in rustup's self-contained dir
	# so we explicitly set the linker search path
	if [ -d "$TARGET_SYSROOT/lib/self-contained" ]; then
		sysroot="$sysroot -B $TARGET_SYSROOT/lib/self-contained"
		sysrootlinkarg="-C link-arg=-B -C link-arg=$TARGET_SYSROOT/lib/self-contained"
	fi
fi

# on linux, we use clang/mold since they supports all architectures
if [[ "$TARGET" != *windows* ]]; then
	static=
	if [[ "$TARGET" == *musl* ]]; then
		# rust automatically makes everything static, for C we need to do it manually
		static=-static
		# musl binaries are portable - optimise them for size
		envs+=("CARGO_PROFILE_RELEASE_OPT_LEVEL=s" "CARGO_PROFILE_RELEASE_PANIC=abort")
	fi
	
	envs+=("CC=clang")
	envs+=("CC_$TARGET=clang")
	envs+=("CXX=clang++")
	envs+=("CXX_$TARGET=clang++")
	envs+=("CFLAGS_$TARGET=-v --target=$TARGET $static -fuse-ld=mold $sysroot $include")
	envs+=("CXXFLAGS_$TARGET=-v --target=$TARGET $static -fuse-ld=mold $sysroot $include")
	envs+=("RUSTFLAGS=-C linker=clang -C link-arg=-v -C link-arg=--target=$TARGET -C link-arg=-fuse-ld=mold $sysrootlinkarg")
fi

# compile crab-hole
env "${envs[@]}" \
	cargo auditable build -v \
		--release --locked \
		--no-default-features --features aws-lc-rs,$ROOTS \
		--target $TARGET

# debug-print the resulting files
lsd -lh --tree || true
file target/$TARGET/release/crab-hole* || true
