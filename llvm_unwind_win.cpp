// This file contains modified parts of the LLVM compiler-rt source code
// (c) Michael Hept 2022. See LICENSE.txt
#include "llvm_stacktrace_defs.h"

#if SANITIZER_WINDOWS
#include "llvm_stacktrace.h"

#define WIN32_LEAN_AND_MEAN
#define NOGDI

#include <windows.h>

namespace llvm_stacktrace {

#if !SANITIZER_GO
void BufferedStackTrace::UnwindSlow(uptr pc, u32 max_depth) {
  CHECK_GE(max_depth, 2);
  // FIXME: CaptureStackBackTrace might be too slow for us.
  // FIXME: Compare with StackWalk64.
  // FIXME: Look at LLVMUnhandledExceptionFilter in Signals.inc
  size = CaptureStackBackTrace(1, Min(max_depth, kStackTraceMax),
                                (void **)&trace_buffer[0], 0);
  if (size == 0)
    return;

  // Skip the RTL frames by searching for the PC in the stacktrace.
  uptr pc_location = LocatePcInTrace(pc);
  PopStackFrames(pc_location);

  // Replace the first frame with the PC because the frame in the
  // stacktrace might be incorrect.
  trace_buffer[0] = pc;
}
#if 0
#ifdef __clang__
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wframe-larger-than="
#endif
void BufferedStackTrace::UnwindSlow(uptr pc, void* context, u32 max_depth) {
  CHECK(context);
  CHECK_GE(max_depth, 2);
  CONTEXT ctx = *(CONTEXT *)context;
  STACKFRAME64 stack_frame;
  memset(&stack_frame, 0, sizeof(stack_frame));

  InitializeDbgHelpIfNeeded();

  size = 0;
#    if SANITIZER_WINDOWS64
#      if SANITIZER_ARM64
  int machine_type = IMAGE_FILE_MACHINE_ARM64;
  stack_frame.AddrPC.Offset = ctx.Pc;
  stack_frame.AddrFrame.Offset = ctx.Fp;
  stack_frame.AddrStack.Offset = ctx.Sp;
#      else
  int machine_type = IMAGE_FILE_MACHINE_AMD64;
  stack_frame.AddrPC.Offset = ctx.Rip;
  stack_frame.AddrFrame.Offset = ctx.Rbp;
  stack_frame.AddrStack.Offset = ctx.Rsp;
#      endif
#    else
  int machine_type = IMAGE_FILE_MACHINE_I386;
  stack_frame.AddrPC.Offset = ctx.Eip;
  stack_frame.AddrFrame.Offset = ctx.Ebp;
  stack_frame.AddrStack.Offset = ctx.Esp;
#    endif
  stack_frame.AddrPC.Mode = AddrModeFlat;
  stack_frame.AddrFrame.Mode = AddrModeFlat;
  stack_frame.AddrStack.Mode = AddrModeFlat;
  while (StackWalk64(machine_type, GetCurrentProcess(), GetCurrentThread(),
                     &stack_frame, &ctx, NULL, SymFunctionTableAccess64,
                     SymGetModuleBase64, NULL) &&
         size < Min(max_depth, kStackTraceMax)) {
    trace_buffer[size++] = (uptr)stack_frame.AddrPC.Offset;
  }
}
#    ifdef __clang__
#      pragma clang diagnostic pop
#    endif
#endif
#  endif  // #if !SANITIZER_GO

}  // namespace llvm_stacktrace

#endif  // SANITIZER_WINDOWS
