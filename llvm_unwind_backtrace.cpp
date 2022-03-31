// This file contains modified parts of the LLVM compiler-rt source code
// (c) Michael Hept 2022. See LICENSE.txt
#include "llvm_stacktrace_defs.h"

#if SANITIZER_FREEBSD || SANITIZER_LINUX || SANITIZER_NETBSD || \
    SANITIZER_SOLARIS
#include "llvm_stacktrace.h"

#if SANITIZER_ANDROID
#include <dlfcn.h>  // for dlopen()
#endif

#if SANITIZER_FREEBSD
#define _GNU_SOURCE  // to declare _Unwind_Backtrace() from <unwind.h>
#endif
#include <unwind.h>

namespace llvm_stacktrace {

namespace {

//---------------------------- UnwindSlow --------------------------------------

typedef struct {
  uptr absolute_pc;
  uptr stack_top;
  uptr stack_size;
} backtrace_frame_t;

#if defined(__arm__) && !SANITIZER_NETBSD
// NetBSD uses dwarf EH
#define UNWIND_STOP _URC_END_OF_STACK
#define UNWIND_CONTINUE _URC_NO_REASON
#else
#define UNWIND_STOP _URC_NORMAL_STOP
#define UNWIND_CONTINUE _URC_NO_REASON
#endif

uptr Unwind_GetIP(struct _Unwind_Context *ctx) {
#if defined(__arm__) && !SANITIZER_MAC
  uptr val;
  _Unwind_VRS_Result res = _Unwind_VRS_Get(ctx, _UVRSC_CORE,
      15 /* r15 = PC */, _UVRSD_UINT32, &val);
  CHECK(res == _UVRSR_OK && "_Unwind_VRS_Get failed");
  // Clear the Thumb bit.
  return val & ~(uptr)1;
#else
  return (uptr)_Unwind_GetIP(ctx);
#endif
}

struct UnwindTraceArg {
  BufferedStackTrace *stack;
  u32 max_depth;
};

_Unwind_Reason_Code Unwind_Trace(struct _Unwind_Context *ctx, void *param) {
  UnwindTraceArg *arg = (UnwindTraceArg*)param;
  CHECK_LT(arg->stack->size, arg->max_depth);
  uptr pc = Unwind_GetIP(ctx);
  const uptr kPageSize = 0x1000;
  // Let's assume that any pointer in the 0th page (i.e. <0x1000 on i386 and
  // x86_64) is invalid and stop unwinding here.  If we're adding support for
  // a platform where this isn't true, we need to reconsider this check.
  if (pc < kPageSize) return UNWIND_STOP;
  arg->stack->trace_buffer[arg->stack->size++] = pc;
  if (arg->stack->size == arg->max_depth) return UNWIND_STOP;
  return UNWIND_CONTINUE;
}

}  // namespace


void BufferedStackTrace::UnwindSlow(uptr pc, u32 max_depth) {
  CHECK_GE(max_depth, 2);
  size = 0;
  UnwindTraceArg arg = {this, Min(max_depth + 1, kStackTraceMax)};
  _Unwind_Backtrace(Unwind_Trace, &arg);
  // We need to pop a few frames so that pc is on top.
  uptr to_pop = LocatePcInTrace(pc);
  // trace_buffer[0] belongs to the current function so we always pop it,
  // unless there is only 1 frame in the stack trace (1 frame is always better
  // than 0!).
  // 1-frame stacks don't normally happen, but this depends on the actual
  // unwinder implementation (libgcc, libunwind, etc) which is outside of our
  // control.
  if (to_pop == 0 && size > 1)
    to_pop = 1;
  PopStackFrames(to_pop);
#if defined(__GNUC__) && defined(__sparc__)
  // __builtin_return_address returns the address of the call instruction
  // on the SPARC and not the return address, so we need to compensate.
  trace_buffer[0] = GetNextInstructionPc(pc);
#else
  trace_buffer[0] = pc;
#endif
}


}  // namespace llvm_stacktrace

#endif  // SANITIZER_FREEBSD || SANITIZER_LINUX || SANITIZER_NETBSD ||
        // SANITIZER_SOLARIS
