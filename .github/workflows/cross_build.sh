#!/usr/bin/env bash
set -exuo pipefail

envs=("RUST_BACKTRACE=1" "CARGO_PROFILE_RELEASE_LTO=true")

# on linux, we use clang/mold since they supports all architectures
if [[ "$TARGET" != *windows* ]]; then
	cflags="-v"
	rustflags="-C linker=clang -C link-arg=-v"

	# add target to flags
	cflags="$cflags --target=$TARGET"
	rustflags="$rustflags -C link-arg=--target=$TARGET"

	# add sysroot flags, including linker search path
	if [ -n "$TARGET_SYSROOT" ]; then
		lsd -lh --tree "$TARGET_SYSROOT"
		# add normal sysroot flag
		cflags="$cflags --sysroot $TARGET_SYSROOT"
		rustflags="$rustflags -C link-arg=--sysroot=$TARGET_SYSROOT"
		# clang/mold ain't smart enough to search in rustup's self-contained dir
		# so we explicitly set the linker search path
		if [ -d "$TARGET_SYSROOT/lib/self-contained" ]; then
			cflags="$cflags -B $TARGET_SYSROOT/lib/self-contained"
			rustflags="$rustflags -C link-arg=-B -C link-arg=$TARGET_SYSROOT/lib/self-contained"
		fi
	fi

	# add libc include dir
	if [ -n "$TARGET_INCLUDE" ]; then
		cflags="$cflags -isystem $TARGET_INCLUDE"
	fi

	if [[ "$TARGET" == *musl* ]]; then
		# we need a compiler runtime, and we don't have access to (pre-compiled) libgcc.a
		llvmver=$(pacman -Qi clang | tr '-' ' ' | awk '/Version/{print $3;}')
		llvmmajor=$(pacman -Qi clang | tr '.' ' ' | awk '/Version/{print $3;}')
		git clone --depth=1 --branch=llvmorg-$llvmver https://github.com/llvm/llvm-project
		cd llvm-project
		mkdir build-compiler-rt
		cd build-compiler-rt
		cmake ../compiler-rt \
			-G Ninja \
			-DCMAKE_AR=/usr/bin/llvm-ar \
			-DCMAKE_ASM_TARGET="$TARGET" \
			-DCMAKE_ASM_FLAGS="$cflags -nostdlib" \
			-DCMAKE_C_COMPILER=/usr/bin/clang \
			-DCMAKE_C_COMPILER_TARGET="$TARGET" \
			-DCMAKE_C_FLAGS="$cflags -nostdlib" \
			-DCMAKE_EXE_LINKER_FLAGS="-fuse-ld=mold" \
			-DCMAKE_NM=/usr/bin/llvm-nm \
			-DCMAKE_RANLIB=/usr/bin/llvm-ranlib \
			-DCOMPILER_RT_BUILD_BUILTINS=ON \
			-DCOMPILER_RT_BUILD_LIBFUZZER=OFF \
			-DCOMPILER_RT_BUILD_MEMPROF=OFF \
			-DCOMPILER_RT_BUILD_PROFILE=OFF \
			-DCOMPILER_RT_BUILD_SANITIZERS=OFF \
			-DCOMPILER_RT_BUILD_XRAY=OFF \
			-DCOMPILER_RT_DEFAULT_TARGET_ONLY=ON \
			-DLLVM_CONFIG_PATH=/usr/bin/llvm-config \
			-DCMAKE_INSTALL_PREFIX="$(llvm-config --prefix)"
		ninja
		ninja install
		cd ../..

		# clang/mold are very strict in their compiler-rt search path
		mkdir -p /usr/lib/clang/$llvmmajor/lib/$TARGET
		ln -s \
			$(realpath $(find llvm-project/build-compiler-rt/ -name 'libclang_rt.builtins*.a' | head -n1)) \
			/usr/lib/clang/$llvmmajor/lib/$TARGET/libclang_rt.builtins.a

		# set the rtlib
		cflags="$cflags -nostartfiles -rtlib=compiler-rt"
		#rustflags="$rustflags -C link-arg=-rtlib=compiler-rt"

		# rust automatically makes everything static, for C we need to do it manually
		cflags="$cflags -static"
		# musl binaries are portable - optimise them for size
		envs+=("CARGO_PROFILE_RELEASE_OPT_LEVEL=s" "CARGO_PROFILE_RELEASE_PANIC=abort")
	fi

	# we'll use mold as the linker
	cflags="$cflags -fuse-ld=mold"
	rustflags="$rustflags -C link-arg=-fuse-ld=mold"

	envs+=("CC=clang")
	envs+=("CC_$TARGET=clang")
	envs+=("CXX=clang++")
	envs+=("CXX_$TARGET=clang++")
	envs+=("CFLAGS_$TARGET=$cflags")
	envs+=("CXXFLAGS_$TARGET=$cflags")
	envs+=("RUSTFLAGS=$rustflags")
fi

# pass include dirs to aws-lc-sys
if [ -n "$TARGET_INCLUDE" ]; then
	envs+=("AWS_LC_SYS_INCLUDES=$TARGET_INCLUDE")
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
