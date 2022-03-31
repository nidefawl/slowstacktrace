// This file contains modified parts of the LLVM compiler-rt source code
// (c) Michael Hept 2022. See LICENSE.txt
#pragma once

#if !defined(__linux__) && !defined(__FreeBSD__) && !defined(__NetBSD__) && \
    !defined(__APPLE__) && !defined(_WIN32) && !defined(__Fuchsia__) &&     \
    !(defined(__sun__) && defined(__svr4__))
#  error "This operating system is not supported"
#endif

// Get __GLIBC__ on a glibc platform. Exclude Android: features.h includes C
// function declarations into a .S file which doesn't compile.
// https://crbug.com/1162741
#if __has_include(<features.h>) && !defined(__ANDROID__)
#  include <features.h>
#endif

#if defined(__linux__)
#  define SANITIZER_LINUX 1
#else
#  define SANITIZER_LINUX 0
#endif

#if defined(__GLIBC__)
#  define SANITIZER_GLIBC 1
#else
#  define SANITIZER_GLIBC 0
#endif

#if defined(__FreeBSD__)
#  define SANITIZER_FREEBSD 1
#else
#  define SANITIZER_FREEBSD 0
#endif

#if defined(__NetBSD__)
#  define SANITIZER_NETBSD 1
#else
#  define SANITIZER_NETBSD 0
#endif

#if defined(__sun__) && defined(__svr4__)
#  define SANITIZER_SOLARIS 1
#else
#  define SANITIZER_SOLARIS 0
#endif

#if defined(__APPLE__)
#  define SANITIZER_MAC 1
#  include <TargetConditionals.h>
#  if TARGET_OS_OSX
#    define SANITIZER_OSX 1
#  else
#    define SANITIZER_OSX 0
#  endif
#  if TARGET_OS_IPHONE
#    define SANITIZER_IOS 1
#  else
#    define SANITIZER_IOS 0
#  endif
#  if TARGET_OS_SIMULATOR
#    define SANITIZER_IOSSIM 1
#  else
#    define SANITIZER_IOSSIM 0
#  endif
#else
#  define SANITIZER_MAC 0
#  define SANITIZER_IOS 0
#  define SANITIZER_IOSSIM 0
#  define SANITIZER_OSX 0
#endif

#if defined(__APPLE__) && TARGET_OS_IPHONE && TARGET_OS_WATCH
#  define SANITIZER_WATCHOS 1
#else
#  define SANITIZER_WATCHOS 0
#endif

#if defined(__APPLE__) && TARGET_OS_IPHONE && TARGET_OS_TV
#  define SANITIZER_TVOS 1
#else
#  define SANITIZER_TVOS 0
#endif

#if defined(_WIN32)
#  define SANITIZER_WINDOWS 1
#else
#  define SANITIZER_WINDOWS 0
#endif

#if defined(_WIN64)
#  define SANITIZER_WINDOWS64 1
#else
#  define SANITIZER_WINDOWS64 0
#endif

#if defined(__ANDROID__)
#  define SANITIZER_ANDROID 1
#else
#  define SANITIZER_ANDROID 0
#endif

#if defined(__Fuchsia__)
#  define SANITIZER_FUCHSIA 1
#else
#  define SANITIZER_FUCHSIA 0
#endif

// Assume linux that is not glibc or android is musl libc.
#if SANITIZER_LINUX && !SANITIZER_GLIBC && !SANITIZER_ANDROID
#  define SANITIZER_MUSL 1
#else
#  define SANITIZER_MUSL 0
#endif

#define SANITIZER_POSIX                                     \
  (SANITIZER_FREEBSD || SANITIZER_LINUX || SANITIZER_MAC || \
   SANITIZER_NETBSD || SANITIZER_SOLARIS)

#if __LP64__ || defined(_WIN64)
#  define SANITIZER_WORDSIZE 64
#else
#  define SANITIZER_WORDSIZE 32
#endif

#if SANITIZER_WORDSIZE == 64
#  define FIRST_32_SECOND_64(a, b) (b)
#else
#  define FIRST_32_SECOND_64(a, b) (a)
#endif

#if defined(__x86_64__) && !defined(_LP64)
#  define SANITIZER_X32 1
#else
#  define SANITIZER_X32 0
#endif

#if defined(__x86_64__) || defined(_M_X64)
#  define SANITIZER_X64 1
#else
#  define SANITIZER_X64 0
#endif

#if defined(__i386__) || defined(_M_IX86)
#  define SANITIZER_I386 1
#else
#  define SANITIZER_I386 0
#endif

#if defined(__mips__)
#  define SANITIZER_MIPS 1
#  if defined(__mips64)
#    define SANITIZER_MIPS32 0
#    define SANITIZER_MIPS64 1
#  else
#    define SANITIZER_MIPS32 1
#    define SANITIZER_MIPS64 0
#  endif
#else
#  define SANITIZER_MIPS 0
#  define SANITIZER_MIPS32 0
#  define SANITIZER_MIPS64 0
#endif

#if defined(__s390__)
#  define SANITIZER_S390 1
#  if defined(__s390x__)
#    define SANITIZER_S390_31 0
#    define SANITIZER_S390_64 1
#  else
#    define SANITIZER_S390_31 1
#    define SANITIZER_S390_64 0
#  endif
#else
#  define SANITIZER_S390 0
#  define SANITIZER_S390_31 0
#  define SANITIZER_S390_64 0
#endif

#if defined(__powerpc__)
#  define SANITIZER_PPC 1
#  if defined(__powerpc64__)
#    define SANITIZER_PPC32 0
#    define SANITIZER_PPC64 1
// 64-bit PPC has two ABIs (v1 and v2).  The old powerpc64 target is
// big-endian, and uses v1 ABI (known for its function descriptors),
// while the new powerpc64le target is little-endian and uses v2.
// In theory, you could convince gcc to compile for their evil twins
// (eg. big-endian v2), but you won't find such combinations in the wild
// (it'd require bootstrapping a whole system, which would be quite painful
// - there's no target triple for that).  LLVM doesn't support them either.
#    if _CALL_ELF == 2
#      define SANITIZER_PPC64V1 0
#      define SANITIZER_PPC64V2 1
#    else
#      define SANITIZER_PPC64V1 1
#      define SANITIZER_PPC64V2 0
#    endif
#  else
#    define SANITIZER_PPC32 1
#    define SANITIZER_PPC64 0
#    define SANITIZER_PPC64V1 0
#    define SANITIZER_PPC64V2 0
#  endif
#else
#  define SANITIZER_PPC 0
#  define SANITIZER_PPC32 0
#  define SANITIZER_PPC64 0
#  define SANITIZER_PPC64V1 0
#  define SANITIZER_PPC64V2 0
#endif

#if defined(__arm__) || defined(_M_ARM)
#  define SANITIZER_ARM 1
#else
#  define SANITIZER_ARM 0
#endif

#if defined(__aarch64__) || defined(_M_ARM64)
#  define SANITIZER_ARM64 1
#else
#  define SANITIZER_ARM64 0
#endif

#if SANITIZER_SOLARIS && SANITIZER_WORDSIZE == 32
#  define SANITIZER_SOLARIS32 1
#else
#  define SANITIZER_SOLARIS32 0
#endif

#if defined(__riscv) && (__riscv_xlen == 64)
#  define SANITIZER_RISCV64 1
#else
#  define SANITIZER_RISCV64 0
#endif


#if defined(__mips__)
#  define SANITIZER_POINTER_FORMAT_LENGTH FIRST_32_SECOND_64(8, 10)
#else
#  define SANITIZER_POINTER_FORMAT_LENGTH FIRST_32_SECOND_64(8, 12)
#endif

#if SANITIZER_GO == 0
#  define SANITIZER_GO 0
#endif

// On PowerPC and ARM Thumb, calling pthread_exit() causes LSan to detect leaks.
// pthread_exit() performs unwinding that leads to dlopen'ing libgcc_s.so.
// dlopen mallocs "libgcc_s.so" string which confuses LSan, it fails to realize
// that this allocation happens in dynamic linker and should be ignored.
#if SANITIZER_PPC || defined(__thumb__)
#  define SANITIZER_SUPPRESS_LEAK_ON_PTHREAD_EXIT 1
#else
#  define SANITIZER_SUPPRESS_LEAK_ON_PTHREAD_EXIT 0
#endif

#if SANITIZER_FREEBSD || SANITIZER_MAC || SANITIZER_NETBSD || SANITIZER_SOLARIS
#  define SANITIZER_MADVISE_DONTNEED MADV_FREE
#else
#  define SANITIZER_MADVISE_DONTNEED MADV_DONTNEED
#endif

// Older gcc have issues aligning to a constexpr, and require an integer.
// See https://gcc.gnu.org/bugzilla/show_bug.cgi?id=56859 among others.
#if defined(__powerpc__) || defined(__powerpc64__)
#  define SANITIZER_CACHE_LINE_SIZE 128
#else
#  define SANITIZER_CACHE_LINE_SIZE 64
#endif

// Enable ability to support sanitizer initialization that is
// compatible with the sanitizer library being loaded via
// `dlopen()`.
#if SANITIZER_MAC
#  define SANITIZER_SUPPORTS_INIT_FOR_DLOPEN 1
#else
#  define SANITIZER_SUPPORTS_INIT_FOR_DLOPEN 0
#endif

#define SANITIZER_STRINGIFY_(S) #S
#define SANITIZER_STRINGIFY(S) SANITIZER_STRINGIFY_(S)

// Only use SANITIZER_*ATTRIBUTE* before the function return type!
#if SANITIZER_WINDOWS
#if SANITIZER_IMPORT_INTERFACE
# define SANITIZER_INTERFACE_ATTRIBUTE __declspec(dllimport)
#else
# define SANITIZER_INTERFACE_ATTRIBUTE __declspec(dllexport)
#endif
# define SANITIZER_WEAK_ATTRIBUTE
#elif SANITIZER_GO
# define SANITIZER_INTERFACE_ATTRIBUTE
# define SANITIZER_WEAK_ATTRIBUTE
#else
# define SANITIZER_INTERFACE_ATTRIBUTE __attribute__((visibility("default")))
# define SANITIZER_WEAK_ATTRIBUTE  __attribute__((weak))
#endif

//--------------------------- WEAK FUNCTIONS ---------------------------------//
// When working with weak functions, to simplify the code and make it more
// portable, when possible define a default implementation using this macro:
//
// SANITIZER_INTERFACE_WEAK_DEF(<return_type>, <name>, <parameter list>)
//
// For example:
//   SANITIZER_INTERFACE_WEAK_DEF(bool, compare, int a, int b) { return a > b; }
//
#if SANITIZER_WINDOWS

#ifndef WINAPI
#if defined(_M_IX86) || defined(__i386__)
#define WINAPI __stdcall
#else
#define WINAPI
#endif
#endif

#if defined(_M_IX86) || defined(__i386__)
#define WIN_SYM_PREFIX "_"
#else
#define WIN_SYM_PREFIX
#endif

// For MinGW, the /export: directives contain undecorated symbols, contrary to
// link/lld-link. The GNU linker doesn't support /alternatename and /include
// though, thus lld-link in MinGW mode interprets them in the same way as
// in the default mode.
#ifdef __MINGW32__
#define WIN_EXPORT_PREFIX
#else
#define WIN_EXPORT_PREFIX WIN_SYM_PREFIX
#endif

# define SANITIZER_INTERFACE_WEAK_DEF(ReturnType, Name, ...)                   \
  WIN_WEAK_EXPORT_DEF(ReturnType, Name, __VA_ARGS__)
#else
# define SANITIZER_INTERFACE_WEAK_DEF(ReturnType, Name, ...)                   \
  extern "C" SANITIZER_INTERFACE_ATTRIBUTE SANITIZER_WEAK_ATTRIBUTE            \
  ReturnType Name(__VA_ARGS__)
#endif

// SANITIZER_SUPPORTS_WEAK_HOOKS means that we support real weak functions that
// will evaluate to a null pointer when not defined.
#ifndef SANITIZER_SUPPORTS_WEAK_HOOKS
#if (SANITIZER_LINUX || SANITIZER_SOLARIS) && !SANITIZER_GO
# define SANITIZER_SUPPORTS_WEAK_HOOKS 1
// Before Xcode 4.5, the Darwin linker doesn't reliably support undefined
// weak symbols.  Mac OS X 10.9/Darwin 13 is the first release only supported
// by Xcode >= 4.5.
#elif SANITIZER_MAC && \
    __ENVIRONMENT_MAC_OS_X_VERSION_MIN_REQUIRED__ >= 1090 && !SANITIZER_GO
# define SANITIZER_SUPPORTS_WEAK_HOOKS 1
#else
# define SANITIZER_SUPPORTS_WEAK_HOOKS 0
#endif
#endif // SANITIZER_SUPPORTS_WEAK_HOOKS
// For some weak hooks that will be called very often and we want to avoid the
// overhead of executing the default implementation when it is not necessary,
// we can use the flag SANITIZER_SUPPORTS_WEAK_HOOKS to only define the default
// implementation for platforms that doesn't support weak symbols. For example:
//
//   #if !SANITIZER_SUPPORT_WEAK_HOOKS
//     SANITIZER_INTERFACE_WEAK_DEF(bool, compare_hook, int a, int b) {
//       return a > b;
//     }
//   #endif
//
// And then use it as: if (compare_hook) compare_hook(a, b);
//----------------------------------------------------------------------------//

namespace llvm_stacktrace {
#if defined(_WIN64)
// 64-bit Windows uses LLP64 data model.
typedef unsigned long long uptr;
typedef signed long long sptr;
#else
#  if (SANITIZER_WORDSIZE == 64) || SANITIZER_MAC || SANITIZER_WINDOWS
typedef unsigned long uptr;
typedef signed long sptr;
#  else
typedef unsigned int uptr;
typedef signed int sptr;
#  endif
#endif  // defined(_WIN64)
#if defined(__x86_64__)
// Since x32 uses ILP32 data model in 64-bit hardware mode, we must use
// 64-bit pointer to unwind stack frame.
typedef unsigned long long uhwptr;
#else
typedef uptr uhwptr;
#endif
typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned int u32;
typedef unsigned long long u64;
typedef signed char s8;
typedef signed short s16;
typedef signed int s32;
typedef signed long long s64;
#if SANITIZER_WINDOWS
// On Windows, files are HANDLE, which is a synonim of void*.
// Use void* to avoid including <windows.h> everywhere.
typedef void* fd_t;
typedef unsigned error_t;
#else
typedef int fd_t;
typedef int error_t;
#endif
#if SANITIZER_SOLARIS && !defined(_LP64)
typedef long pid_t;
#else
typedef int pid_t;
#endif

// Common defs.
#define INTERFACE_ATTRIBUTE SANITIZER_INTERFACE_ATTRIBUTE
#define SANITIZER_WEAK_DEFAULT_IMPL \
  extern "C" SANITIZER_INTERFACE_ATTRIBUTE SANITIZER_WEAK_ATTRIBUTE NOINLINE
#define SANITIZER_WEAK_CXX_DEFAULT_IMPL \
  extern "C++" SANITIZER_INTERFACE_ATTRIBUTE SANITIZER_WEAK_ATTRIBUTE NOINLINE

// Platform-specific defs.
#if defined(_MSC_VER)
# define ALWAYS_INLINE __forceinline
// FIXME(timurrrr): do we need this on Windows?
# define FORMAT(f, a)
# define NOINLINE __declspec(noinline)
# define NORETURN __declspec(noreturn)
# define LIKELY(x) (x)
# define UNLIKELY(x) (x)
#else  // _MSC_VER
# define ALWAYS_INLINE inline __attribute__((always_inline))
// Please only use the ALIGNED macro before the type.
# define FORMAT(f, a)  __attribute__((format(printf, f, a)))
# define NOINLINE __attribute__((noinline))
# define NORETURN  __attribute__((noreturn))
# define LIKELY(x)     __builtin_expect(!!(x), 1)
# define UNLIKELY(x)   __builtin_expect(!!(x), 0)
#endif  // _MSC_VER

void failed_check();

// Check macro
#define RAW_CHECK_MSG(expr, msg, ...)                                          \
  do {                                                                         \
    if (UNLIKELY(!(expr))) {                                                   \
      const char *msgs[] = {msg, __VA_ARGS__};                                 \
      for (const char *m : msgs)                                               \
        llvm_stacktrace::RawWrite(m);                                          \
      failed_check();                                                          \
    }                                                                          \
  } while (0)

#define RAW_CHECK(expr) RAW_CHECK_MSG(expr, #expr "\n", )
#define RAW_CHECK_VA(expr, ...) RAW_CHECK_MSG(expr, #expr "\n", __VA_ARGS__)

#define CHECK_IMPL(c1, op, c2)                                                 \
  do {                                                                         \
    u64 v1 = (u64)(c1);                                                        \
    u64 v2 = (u64)(c2);                                                        \
    if (UNLIKELY(!(v1 op v2))) {                                               \
      llvm_stacktrace::Printf(                                                 \
          "llvm_stacktrace CHECK failed: %s:%d \"%s\" (0x%zx, 0x%zx)\n",       \
          StripModuleName(__FILE__), __LINE__, "(" #c1 ") " #op " (" #c2 ")",  \
          (uptr)v1, (uptr)v2);                                                 \
      failed_check();                                                          \
    }                                                                          \
  } while (false)
/**/

#define CHECK(a)       CHECK_IMPL((a), !=, 0)
#define CHECK_EQ(a, b) CHECK_IMPL((a), ==, (b))
#define CHECK_NE(a, b) CHECK_IMPL((a), !=, (b))
#define CHECK_LT(a, b) CHECK_IMPL((a), <,  (b))
#define CHECK_LE(a, b) CHECK_IMPL((a), <=, (b))
#define CHECK_GT(a, b) CHECK_IMPL((a), >,  (b))
#define CHECK_GE(a, b) CHECK_IMPL((a), >=, (b))

#define UNIMPLEMENTED() Report("unimplemented"); return false;

#define ARRAY_SIZE(a) (sizeof(a)/sizeof((a)[0]))

#if !defined(_MSC_VER) || defined(__clang__)
#if SANITIZER_S390_31
#define GET_CALLER_PC() \
  (llvm_stacktrace::uptr) __builtin_extract_return_addr(__builtin_return_address(0))
#else
#define GET_CALLER_PC() (llvm_stacktrace::uptr) __builtin_return_address(0)
#endif
#define GET_CURRENT_FRAME() (llvm_stacktrace::uptr) __builtin_frame_address(0)
#else
extern "C" void* _ReturnAddress(void);
extern "C" void* _AddressOfReturnAddress(void);
# pragma intrinsic(_ReturnAddress)
# pragma intrinsic(_AddressOfReturnAddress)
#define GET_CALLER_PC() (llvm_stacktrace::uptr) _ReturnAddress()
// CaptureStackBackTrace doesn't need to know BP on Windows.
#define GET_CURRENT_FRAME() \
  (((llvm_stacktrace::uptr)_AddressOfReturnAddress()) + sizeof(llvm_stacktrace::uptr))

extern "C" void __ud2(void);
# pragma intrinsic(__ud2)
#endif

inline constexpr uptr RoundUpTo(uptr size, uptr boundary) {
  return (size + boundary - 1) & ~(boundary - 1);
}

// Don't use std::min, std::max or std::swap, to minimize dependency
// on libstdc++.
template <class T>
constexpr T Min(T a, T b) {
  return a < b ? a : b;
}
template <class T>
constexpr T Max(T a, T b) {
  return a > b ? a : b;
}
template <class T>
constexpr T Abs(T a) {
  return a < 0 ? -a : a;
}
template<class T> void Swap(T& a, T& b) {
  T tmp = a;
  a = b;
  b = tmp;
}

// Char handling
inline bool IsSpace(int c) {
  return (c == ' ') || (c == '\n') || (c == '\t') ||
         (c == '\f') || (c == '\r') || (c == '\v');
}
inline bool IsDigit(int c) {
  return (c >= '0') && (c <= '9');
}
inline int ToLower(int c) {
  return (c >= 'A' && c <= 'Z') ? (c + 'a' - 'A') : c;
}

}