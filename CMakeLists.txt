cmake_minimum_required(VERSION 3.23)
project(yulong_km C)


set(CMAKE_C_STANDARD 90)

add_definitions(-D__KERNEL__)
add_definitions(-DYULONG)
add_definitions(-DCONFIG_NETFILTER)
add_definitions(-D__LOCAL_TEST__)
set(CMAKE_INCLUDE_DIRECTORIES_BEFORE ON)
#set(kernel_base "~/rpmbuild/BUILD/kernel-4.19.248.zzz")
set(kernel_base "~/rpmbuild/BUILD/kernel-4.19.248.yl.2023H2")

include_directories(BEFORE SYSTEM ${kernel_base}/include)
include_directories(BEFORE SYSTEM ${kernel_base}/arch/x86/include/)
add_definitions(-DCONFIG_DEBUG_LIST)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/src)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/src/compat)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/src/compat/simd/include)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/src/crypto/include)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/src/uapi)

include_directories(${CMAKE_CURRENT_SOURCE_DIR}/src/yulong)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/src/yulong/hook)

add_library(yulong_km
        src/compat/memneq/memneq.c
        src/compat/dst_cache/dst_cache.c
        src/compat/udp_tunnel/udp_tunnel.c
        src/compat/siphash/siphash.c
        src/send.c
        src/allowedips.c
        src/crypto/zinc/blake2s/blake2s-x86_64-glue.c
        src/crypto/zinc/blake2s/blake2s.c
        src/crypto/zinc/poly1305/poly1305-arm-glue.c
        src/crypto/zinc/poly1305/poly1305-mips-glue.c
        src/crypto/zinc/poly1305/poly1305-donna64.c
        src/crypto/zinc/poly1305/poly1305.c
        src/crypto/zinc/poly1305/poly1305-donna32.c
        src/crypto/zinc/poly1305/poly1305-x86_64-glue.c
        src/crypto/zinc/chacha20/chacha20.c
        src/crypto/zinc/chacha20/chacha20-mips-glue.c
        src/crypto/zinc/chacha20/chacha20-x86_64-glue.c
        src/crypto/zinc/chacha20/chacha20-arm-glue.c
        src/crypto/zinc/selftest/chacha20.c
        src/crypto/zinc/selftest/curve25519.c
        src/crypto/zinc/selftest/blake2s.c
        src/crypto/zinc/selftest/poly1305.c
        src/crypto/zinc/selftest/chacha20poly1305.c
        src/crypto/zinc/chacha20poly1305.c
        src/crypto/zinc/curve25519/curve25519-x86_64-glue.c
        src/crypto/zinc/curve25519/curve25519.c
        src/crypto/zinc/curve25519/curve25519-arm-glue.c
        src/crypto/zinc/curve25519/curve25519-x86_64.c
        src/crypto/zinc/curve25519/curve25519-hacl64.c
        src/crypto/zinc/curve25519/curve25519-fiat32.c
        src/main.c
        src/device.c
        src/selftest/allowedips.c
        src/selftest/counter.c
        src/selftest/ratelimiter.c
        src/receive.c
        src/queueing.c
        src/peerlookup.c
        src/socket.c
        src/cookie.c
        src/timers.c
        src/ratelimiter.c
        src/noise.c
        src/netlink.c
        src/tests/qemu/init.c
        src/peer.c
        src/compat/neon-arm/include/asm/neon.h
        src/compat/skb_array/include/linux/skb_array.h
        src/compat/simd/include/linux/simd.h
        src/compat/memneq/include.h
        src/compat/ptr_ring/include/linux/ptr_ring.h
        src/compat/simd-asm/include/asm/simd.h
        src/compat/intel-family-x86/include/asm/intel-family.h
        src/compat/dst_cache/include/net/dst_cache.h
        src/compat/udp_tunnel/udp_tunnel_partial_compat.h
        src/compat/udp_tunnel/include/net/udp_tunnel.h
        src/compat/version/linux/version.h
        src/compat/dstmetadata/include/net/dst_metadata.h
        src/compat/compat.h
        src/compat/compat-asm.h
        src/compat/siphash/include/linux/siphash.h
        src/compat/fpu-x86/include/asm/fpu/api.h
        src/peer.h
        src/noise.h
        src/socket.h
        src/peerlookup.h
        src/cookie.h
        src/crypto/zinc/selftest/run.h
        src/crypto/zinc.h
        src/crypto/include/zinc/poly1305.h
        src/crypto/include/zinc/curve25519.h
        src/crypto/include/zinc/chacha20.h
        src/crypto/include/zinc/chacha20poly1305.h
        src/crypto/include/zinc/blake2s.h
        src/netlink.h
        src/uapi/wireguard.h
        src/timers.h
        src/ratelimiter.h
        src/queueing.h
        src/version.h
        src/device.h
        src/allowedips.h
        src/messages.h
        src/yulong/skb_utils.c src/yulong/skb_utils.h
        src/yulong/yulong.c
        src/yulong/yulongnl.c
        src/yulong/ylflow.c
        src/yulong/sys_wait.c
        src/yulong/cache_common.c
        src/yulong/hook/connect.c
        src/yulong/hook/init.c
        src/yulong/hook/sendto.c
        src/yulong/hook/syscall_map.c
        )
