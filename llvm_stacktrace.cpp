// This file contains modified parts of the LLVM compiler-rt source code
// (c) Michael Hept 2022. See LICENSE.txt

#include "llvm_stacktrace.h"
#include "llvm_string.h"
#include "llvm_symbolizer.h"
#include <assert.h>
#include <cstdlib>

namespace llvm_stacktrace {

void failed_check() {
  assert(0);
  exit(1);
}

uptr StackTrace::GetNextInstructionPc(uptr pc) {
#if defined(__aarch64__)
  return STRIP_PAC_PC((void *)pc) + 4;
#elif defined(__sparc__) || defined(__mips__)
  return pc + 8;
#elif SANITIZER_RISCV64
  // Current check order is 4 -> 2 -> 6 -> 8
  u8 InsnByte = *(u8 *)(pc);
  if (((InsnByte & 0x3) == 0x3) && ((InsnByte & 0x1c) != 0x1c)) {
    // xxxxxxxxxxxbbb11 | 32 bit | bbb != 111
    return pc + 4;
  }
  if ((InsnByte & 0x3) != 0x3) {
    // xxxxxxxxxxxxxxaa | 16 bit | aa != 11
    return pc + 2;
  }
  // RISC-V encoding allows instructions to be up to 8 bytes long
  if ((InsnByte & 0x3f) == 0x1f) {
    // xxxxxxxxxx011111 | 48 bit |
    return pc + 6;
  }
  if ((InsnByte & 0x7f) == 0x3f) {
    // xxxxxxxxx0111111 | 64 bit |
    return pc + 8;
  }
  // bail-out if could not figure out the instruction size
  return 0;
#elif SANITIZER_S390 || SANITIZER_I386 || SANITIZER_X32 || SANITIZER_X64
  return pc + 1;
#else
  return pc + 4;
#endif
}

uptr StackTrace::GetCurrentPc() {
  return GET_CALLER_PC();
}

void BufferedStackTrace::PopStackFrames(uptr count) {
  CHECK_LT(count, size);
  size -= count;
  for (uptr i = 0; i < size; ++i) {
    trace_buffer[i] = trace_buffer[i + count];
  }
}

static uptr Distance(uptr a, uptr b) { return a < b ? b - a : a - b; }

uptr BufferedStackTrace::LocatePcInTrace(uptr pc) {
  uptr best = 0;
  for (uptr i = 1; i < size; ++i) {
    if (Distance(trace[i], pc) < Distance(trace[best], pc)) best = i;
  }
  return best;
}

void BufferedStackTrace::UnwindImpl(
    uptr pc, uptr bp, u32 max_depth) {
  size = 0;
  // Ensures all call sites get what they requested.
  top_frame_bp = (max_depth > 0) ? bp : 0;
  // Avoid doing any work for small max_depth.
  if (max_depth == 0) {
    size = 0;
    return;
  }
  if (max_depth == 1) {
    size = 1;
    trace_buffer[0] = pc;
    return;
  }
  UnwindSlow(pc, max_depth);
}

static const char kDefaultFormat[] = "    #%n %p %F %L";


const char *StripModuleName(const char *module) {
  if (!module)
    return nullptr;
  if (SANITIZER_WINDOWS) {
    // On Windows, both slash and backslash are possible.
    // Pick the one that goes last.
    if (const char *bslash_pos = std::strrchr(module, '\\'))
      return StripModuleName(bslash_pos + 1);
  }
  if (const char *slash_pos = std::strrchr(module, '/')) {
    return slash_pos + 1;
  }
  return module;
}
namespace {

const char *StripPathPrefix(const char *filepath,
                            const char *strip_path_prefix) {
  if (!filepath) return nullptr;
  if (!strip_path_prefix) return filepath;
  const char *res = filepath;
  if (const char *pos = std::strstr(filepath, strip_path_prefix))
    res = pos + std::strlen(strip_path_prefix);
  if (res[0] == '.' && res[1] == '/')
    res += 2;
  return res;
}
static void MaybeBuildIdToBuffer(const AddressInfo &info, bool PrefixSpace,
                                 InternalScopedString *buffer) {
  if (info.uuid_size) {
    if (PrefixSpace)
      buffer->append(" ");
    buffer->append("(BuildId: ");
    for (uptr i = 0; i < info.uuid_size; ++i) {
      buffer->append("%02x", info.uuid[i]);
    }
    buffer->append(")");
  }
}
static const char *StripFunctionName(const char *function, const char *prefix) {
  if (!function) return nullptr;
  if (!prefix) return function;
  uptr prefix_len = std::strlen(prefix);
  if (0 == std::strncmp(function, prefix, prefix_len))
    return function + prefix_len;
  return function;
}
void RenderSourceLocation(InternalScopedString *buffer, const char *file,
                          int line, int column, bool vs_style,
                          const char *strip_path_prefix) {
  if (vs_style && line > 0) {
    buffer->append("%s(%d", StripPathPrefix(file, strip_path_prefix), line);
    if (column > 0)
      buffer->append(",%d", column);
    buffer->append(")");
    return;
  }

  buffer->append("%s", StripPathPrefix(file, strip_path_prefix));
  if (line > 0) {
    buffer->append(":%d", line);
    if (column > 0)
      buffer->append(":%d", column);
  }
}

void RenderModuleLocation(InternalScopedString *buffer, const char *module,
                          uptr offset, ModuleArch arch,
                          const char *strip_path_prefix) {
  buffer->append("(%s", StripPathPrefix(module, strip_path_prefix));
  if (arch != kModuleArchUnknown) {
    buffer->append(":%s", ModuleArchToString(arch));
  }
  buffer->append("+0x%zx)", offset);
}

  
void RenderFrame(InternalScopedString *buffer, const char *format, int frame_no,
                 uptr address, const AddressInfo *info, bool vs_style,
                 const char *strip_path_prefix, const char *strip_func_prefix) {
  // info will be null in the case where symbolization is not needed for the
  // given format. This ensures that the code below will get a hard failure
  // rather than print incorrect information in case RenderNeedsSymbolization
  // ever ends up out of sync with this function. If non-null, the addresses
  // should match.
  CHECK(!info || address == info->address);
  if (0 == std::strcmp(format, "DEFAULT"))
    format = kDefaultFormat;
  for (const char *p = format; *p != '\0'; p++) {
    if (*p != '%') {
      buffer->append("%c", *p);
      continue;
    }
    p++;
    switch (*p) {
    case '%':
      buffer->append("%%");
      break;
    // Frame number and all fields of AddressInfo structure.
    case 'n':
      buffer->append("%u", frame_no);
      break;
    case 'p':
      buffer->append("0x%zx", address);
      break;
    case 'm':
      buffer->append("%s", StripPathPrefix(info->module, strip_path_prefix));
      break;
    case 'o':
      buffer->append("0x%zx", info->module_offset);
      break;
    case 'b':
      MaybeBuildIdToBuffer(*info, /*PrefixSpace=*/false, buffer);
      break;
    case 'f':
      buffer->append("%s", StripFunctionName(
                               info->function, strip_func_prefix));
      break;
    case 'q':
      buffer->append("0x%zx", info->function_offset != AddressInfo::kUnknown
                                  ? info->function_offset
                                  : 0x0);
      break;
    case 's':
      buffer->append("%s", StripPathPrefix(info->file, strip_path_prefix));
      break;
    case 'l':
      buffer->append("%d", info->line);
      break;
    case 'c':
      buffer->append("%d", info->column);
      break;
    // Smarter special cases.
    case 'F':
      // Function name and offset, if file is unknown.
      if (info->function) {
        buffer->append("in %s", StripFunctionName(
                                    info->function, strip_func_prefix));
        if (!info->file && info->function_offset != AddressInfo::kUnknown)
          buffer->append("+0x%zx", info->function_offset);
      }
      break;
    case 'S':
      // File/line information.
      RenderSourceLocation(buffer, info->file, info->line, info->column,
                           vs_style, strip_path_prefix);
      break;
    case 'L':
      // Source location, or module location.
      if (info->file) {
        RenderSourceLocation(buffer, info->file, info->line, info->column,
                             vs_style, strip_path_prefix);
      } else if (info->module) {
        RenderModuleLocation(buffer, info->module, info->module_offset,
                             info->module_arch, strip_path_prefix);

        MaybeBuildIdToBuffer(*info, /*PrefixSpace=*/true, buffer);
      } else {
        buffer->append("(<unknown module>)");
      }
      break;
    case 'M':
      // Module basename and offset, or PC.
      if (address & kExternalPCBit) {
        // There PCs are not meaningful.
      } else if (info->module) {
        // Always strip the module name for %M.
        RenderModuleLocation(buffer, StripModuleName(info->module),
                             info->module_offset, info->module_arch, "");
        MaybeBuildIdToBuffer(*info, /*PrefixSpace=*/true, buffer);
      } else {
        buffer->append("(%p)", (void *)address);
      }
      break;
    default:
      Report("Unsupported specifier in stack frame format: %c (%p)!\n", *p,
             (void *)p);
      // Die();
    }
  }
}
bool RenderNeedsSymbolization(const char *format) {
  if (0 == std::strcmp(format, "DEFAULT"))
    format = kDefaultFormat;
  for (const char *p = format; *p != '\0'; p++) {
    if (*p != '%')
      continue;
    p++;
    switch (*p) {
      case '%':
        break;
      case 'n':
        // frame_no
        break;
      case 'p':
        // address
        break;
      default:
        return true;
    }
  }
  return false;
}
}

class StackTraceTextPrinter {
 public:
  StackTraceTextPrinter(const char *stack_trace_fmt, char frame_delimiter,
                        InternalScopedString *output,
                        InternalScopedString *dedup_token)
      : stack_trace_fmt_(stack_trace_fmt),
        frame_delimiter_(frame_delimiter),
        output_(output),
        dedup_token_(dedup_token),
        symbolize_(RenderNeedsSymbolization(stack_trace_fmt)) {}

  bool ProcessAddressFrames(uptr pc) {
    // SymbolizedStack *frames = Symbolizer::GetOrInit()->SymbolizePC(pc);
    if (symbolize_ && !this->symbolizer_) {
      this->symbolizer_ = Symbolizer::GetOrInit();
    }
    SymbolizedStack *frames = this->symbolizer_
                                  ? this->symbolizer_->SymbolizePC(pc)
                                  : SymbolizedStack::New(pc);
    if (!frames)
      return false;

    for (SymbolizedStack *cur = frames; cur; cur = cur->next) {
      uptr prev_len = output_->length();
      RenderFrame(output_, stack_trace_fmt_, frame_num_++, cur->info.address,
                  symbolize_ ? &cur->info : nullptr,
                  false,
                  nullptr, nullptr);

      if (prev_len != output_->length())
        output_->append("%c", frame_delimiter_);

      ExtendDedupToken(cur);
    }
    frames->ClearAll();
    delete frames;
    return true;
  }

 private:
  // Extend the dedup token by appending a new frame.
  void ExtendDedupToken(SymbolizedStack *stack) {
    if (!dedup_token_)
      return;

    if (dedup_frames_-- > 0) {
      if (dedup_token_->length())
        dedup_token_->append("--");
      if (stack->info.function != nullptr)
        dedup_token_->append("%s", stack->info.function);
    }
  }

  const char *stack_trace_fmt_;
  const char frame_delimiter_;
  int dedup_frames_ = 0;
  uptr frame_num_ = 0;
  InternalScopedString *output_;
  InternalScopedString *dedup_token_;
  const bool symbolize_ = false;
  Symbolizer* symbolizer_ = nullptr;
};

static void CopyStringToBuffer(const InternalScopedString &str, char *out_buf,
                               uptr out_buf_size) {
  if (!out_buf_size)
    return;

  CHECK_GT(out_buf_size, 0);
  uptr copy_size = Min(str.length(), out_buf_size - 1);
  std::memcpy(out_buf, str.data(), copy_size);
  out_buf[copy_size] = '\0';
}


void StackTrace::PrintTo(InternalScopedString *output, const char* stack_trace_format) const {
  CHECK(output);

  if (trace == nullptr || size == 0) {
    output->append("    <empty stack>\n\n");
    return;
  }

  if (!stack_trace_format) {
    stack_trace_format = kDefaultFormat;
  }

  InternalScopedString dedup_token;
  StackTraceTextPrinter printer(stack_trace_format, '\n',
                                output, &dedup_token);

  for (uptr i = 0; i < size && trace[i]; i++) {
    // PCs in stack traces are actually the return addresses, that is,
    // addresses of the next instructions after the call.
    uptr pc = GetPreviousInstructionPc(trace[i]);
    CHECK(printer.ProcessAddressFrames(pc));
  }

  // Always add a trailing empty line after stack trace.
  output->append("\n");

  // Append deduplication token, if non-empty.
  if (dedup_token.length())
    output->append("DEDUP_TOKEN: %s\n", dedup_token.data());
}

uptr StackTrace::PrintTo(char *out_buf, uptr out_buf_size, const char* stack_trace_format) const {
  CHECK(out_buf);

  InternalScopedString output;
  PrintTo(&output, stack_trace_format);
  CopyStringToBuffer(output, out_buf, out_buf_size);

  return output.length();
}

void StackTrace::Print(const char* stack_trace_format) const {
  InternalScopedString output;
  PrintTo(&output, stack_trace_format);
  Printf("%s", output.data());
}

}  // namespace llvm_stacktrace
