// This file contains modified parts of the LLVM compiler-rt source code
// (c) Michael Hept 2022. See LICENSE.txt
#include "llvm_stacktrace_defs.h"

#include "llvm_stacktrace.h"
#include "llvm_string.h"
#include "llvm_symbolizer.h"
#include "llvm_symbolizer_internal.h"


#include <cstdio>
#include <cstdlib>
#include <cstring>

namespace llvm_stacktrace {

Symbolizer *Symbolizer::GetOrInit() {
  return PlatformInit();
}

static const char kPathSeparator = SANITIZER_WINDOWS ? ';' : ':';

char *internal_strchrnul(const char *s, int c) {
  auto res = const_cast<char *>(std::strchr(s, c));
  if (!res)
    return const_cast<char *>(s) + std::strlen(s);
  return res;
}

bool FindPathToBinary(const char *name, InternalScopedString& binary_path) {
  if (FileExists(name)) {
    binary_path.set(name);
    return true;
  }

  const char *path = std::getenv("PATH");
  if (!path)
    return false;
  uptr name_len = std::strlen(name);
  std::vector<char> buffer(kMaxPathLength);
  const char *beg = path;
  while (true) {
    const char *end = internal_strchrnul(beg, kPathSeparator);
    uptr prefix_len = end - beg;
    if (prefix_len + name_len + 2 <= kMaxPathLength) {
      std::memcpy(buffer.data(), beg, prefix_len);
      buffer[prefix_len] = '/';
      std::memcpy(&buffer[prefix_len + 1], name, name_len);
      buffer[prefix_len + 1 + name_len] = '\0';
      if (FileExists(buffer.data())) {
        binary_path.set(buffer.data());
        return true;
      }
    }
    if (*end == '\0') break;
    beg = end + 1;
  }
  return false;
}

// For now we assume the following protocol:
// For each request of the form
//   <module_name> <module_offset>
// passed to STDIN, external symbolizer prints to STDOUT response:
//   <function_name>
//   <file_name>:<line_number>:<column_number>
//   <function_name>
//   <file_name>:<line_number>:<column_number>
//   ...
//   <empty line>
class LLVMSymbolizerProcess final : public SymbolizerProcess {
 public:
  explicit LLVMSymbolizerProcess(const char *path)
      : SymbolizerProcess(path, /*use_posix_spawn=*/SANITIZER_MAC) {}

 private:
  bool ReachedEndOfOutput(const char *buffer, uptr length) const override {
    // Empty line marks the end of llvm-symbolizer output.
    return length >= 2 && buffer[length - 1] == '\n' &&
           buffer[length - 2] == '\n';
  }

  // When adding a new architecture, don't forget to also update
  // script/asan_symbolize.py and sanitizer_common.h.
  bool GetArgV(const char *path_to_binary,
               const char *(&argv)[kArgVMax]) const override {
#if defined(__x86_64h__)
    const char* const kSymbolizerArch = "--default-arch=x86_64h";
#elif defined(__x86_64__)
    const char* const kSymbolizerArch = "--default-arch=x86_64";
#elif defined(__i386__)
    const char* const kSymbolizerArch = "--default-arch=i386";
#elif SANITIZER_RISCV64
    const char *const kSymbolizerArch = "--default-arch=riscv64";
#elif defined(__aarch64__)
    const char* const kSymbolizerArch = "--default-arch=arm64";
#elif defined(__arm__)
    const char* const kSymbolizerArch = "--default-arch=arm";
#elif defined(__powerpc64__) && __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
    const char* const kSymbolizerArch = "--default-arch=powerpc64";
#elif defined(__powerpc64__) && __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
    const char* const kSymbolizerArch = "--default-arch=powerpc64le";
#elif defined(__s390x__)
    const char* const kSymbolizerArch = "--default-arch=s390x";
#elif defined(__s390__)
    const char* const kSymbolizerArch = "--default-arch=s390";
#else
    const char* const kSymbolizerArch = "--default-arch=unknown";
#endif
    const bool demangle = true;
    const bool symbolize_inline_frames = true;
    const char *const demangle_flag =
        demangle ? "--demangle" : "--no-demangle";
    const char *const inline_flag =
        symbolize_inline_frames ? "--inlines" : "--no-inlines";
    int i = 0;
    argv[i++] = path_to_binary;
    argv[i++] = demangle_flag;
    argv[i++] = inline_flag;
    argv[i++] = kSymbolizerArch;
    argv[i++] = nullptr;
    CHECK_LE(i, kArgVMax);
    return true;
  }
};

LLVMSymbolizer::LLVMSymbolizer(const char *path)
    : symbolizer_process_(new LLVMSymbolizerProcess(path)) {}

LLVMSymbolizer::~LLVMSymbolizer() {
  delete symbolizer_process_;
}

const char *ExtractToken(const char *str, const char *delims, char **result) {
  uptr prefix_len = std::strcspn(str, delims);
  *result = (char*)std::malloc(prefix_len + 1);
  std::memcpy(*result, str, prefix_len);
  (*result)[prefix_len] = '\0';
  const char *prefix_end = str + prefix_len;
  if (*prefix_end != '\0') prefix_end++;
  return prefix_end;
}

const char *ExtractUptr(const char *str, const char *delims, uptr *result) {
  char *buff = nullptr;
  const char *ret = ExtractToken(str, delims, &buff);
  if (buff) {
    *result = (uptr)std::atoll(buff);
  }
  std::free(buff);
  return ret;
}

const char *ExtractSptr(const char *str, const char *delims, sptr *result) {
  char *buff = nullptr;
  const char *ret = ExtractToken(str, delims, &buff);
  if (buff) {
    *result = (sptr)std::atoll(buff);
  }
  std::free(buff);
  return ret;
}
// Parse a <file>:<line>[:<column>] buffer. The file path may contain colons on
// Windows, so extract tokens from the right hand side first. The column info is
// also optional.
static const char *ParseFileLineInfo(AddressInfo *info, const char *str) {
  char *file_line_info = nullptr;
  str = ExtractToken(str, "\n", &file_line_info);
  CHECK(file_line_info);

  if (uptr size = std::strlen(file_line_info)) {
    char *back = file_line_info + size - 1;
    for (int i = 0; i < 2; ++i) {
      while (back > file_line_info && IsDigit(*back)) --back;
      if (*back != ':' || !IsDigit(back[1])) break;
      info->column = info->line;
      info->line = std::atoll(back + 1);
      // Truncate the string at the colon to keep only filename.
      *back = '\0';
      --back;
    }
    ExtractToken(file_line_info, "", &info->file);
  }

  std::free(file_line_info);
  return str;
}

// Parses one or more two-line strings in the following format:
//   <function_name>
//   <file_name>:<line_number>[:<column_number>]
// Used by LLVMSymbolizer, Addr2LinePool and InternalSymbolizer, since all of
// them use the same output format.
void ParseSymbolizePCOutput(const char *str, SymbolizedStack *res) {
  bool top_frame = true;
  SymbolizedStack *last = res;
  while (true) {
    char *function_name = nullptr;
    str = ExtractToken(str, "\n", &function_name);
    CHECK(function_name);
    if (function_name[0] == '\0') {
      // There are no more frames.
      std::free(function_name);
      break;
    }
    SymbolizedStack *cur;
    if (top_frame) {
      cur = res;
      top_frame = false;
    } else {
      cur = SymbolizedStack::New(res->info.address);
      cur->info.FillModuleInfo(res->info.module, res->info.module_offset,
                               res->info.module_arch);
      last->next = cur;
      last = cur;
    }

    AddressInfo *info = &cur->info;
    info->function = function_name;
    str = ParseFileLineInfo(info, str);

    // Functions and filenames can be "??", in which case we write 0
    // to address info to mark that names are unknown.
    if (0 == std::strcmp(info->function, "??")) {
      std::free(info->function);
      info->function = 0;
    }
    if (info->file && 0 == std::strcmp(info->file, "??")) {
      std::free(info->file);
      info->file = 0;
    }
  }
}

// Parses a two-line string in the following format:
//   <symbol_name>
//   <start_address> <size>
// Used by LLVMSymbolizer and InternalSymbolizer.
void ParseSymbolizeDataOutput(const char *str, DataInfo *info) {
  str = ExtractToken(str, "\n", &info->name);
  str = ExtractUptr(str, " ", &info->start);
  str = ExtractUptr(str, "\n", &info->size);
}

static void ParseSymbolizeFrameOutput(const char *str,
                                      std::vector<LocalInfo> *locals) {
  if (std::strncmp(str, "??", 2) == 0)
    return;

  while (*str) {
    LocalInfo local;
    str = ExtractToken(str, "\n", &local.function_name);
    str = ExtractToken(str, "\n", &local.name);

    AddressInfo addr;
    str = ParseFileLineInfo(&addr, str);
    local.decl_file = addr.file;
    local.decl_line = addr.line;

    local.has_frame_offset = std::strncmp(str, "??", 2) != 0;
    str = ExtractSptr(str, " ", &local.frame_offset);

    local.has_size = std::strncmp(str, "??", 2) != 0;
    str = ExtractUptr(str, " ", &local.size);

    local.has_tag_offset = std::strncmp(str, "??", 2) != 0;
    str = ExtractUptr(str, "\n", &local.tag_offset);

    locals->push_back(local);
  }
}

const char *LLVMSymbolizer::FormatAndSendCommand(const char *command_prefix,
                                                 const char *module_name,
                                                 uptr module_offset,
                                                 ModuleArch arch) {
  CHECK(module_name);
  int size_needed = 0;
  if (arch == kModuleArchUnknown)
    size_needed = snprintf(buffer_, kBufferSize, "%s \"%s\" 0x%zx\n",
                                    command_prefix, module_name, module_offset);
  else
    size_needed = snprintf(buffer_, kBufferSize,
                                    "%s \"%s:%s\" 0x%zx\n", command_prefix,
                                    module_name, ModuleArchToString(arch),
                                    module_offset);

  if (size_needed >= static_cast<int>(kBufferSize)) {
    Report("WARNING: Command buffer too small");
    return nullptr;
  }

  return symbolizer_process_->SendCommand(buffer_);
}

SymbolizerProcess::SymbolizerProcess(const char *path, bool use_posix_spawn)
    : path_(strdup(path)),
      input_fd_(kInvalidFd),
      output_fd_(kInvalidFd),
      times_restarted_(0),
      failed_to_start_(false),
      reported_invalid_path_(false),
      use_posix_spawn_(use_posix_spawn) {
  CHECK(path_);
  CHECK_NE(path_[0], '\0');
}

const char *SymbolizerProcess::SendCommand(const char *command) {
  if (failed_to_start_)
    return nullptr;
  for (; times_restarted_ < kMaxTimesRestarted; times_restarted_++) {
    // Start or restart symbolizer if we failed to send command to it.
    if (const char *res = SendCommandImpl(command))
      return res;
    Restart();
  }
  if (!failed_to_start_) {
    Report("WARNING: Failed to use and restart external symbolizer!\n");
    failed_to_start_ = true;
  }
  return nullptr;
}

const char *SymbolizerProcess::SendCommandImpl(const char *command) {
  if (input_fd_ == kInvalidFd || output_fd_ == kInvalidFd)
      return nullptr;
  if (!WriteToSymbolizer(command, std::strlen(command)))
      return nullptr;
  if (!ReadFromSymbolizer(buffer_, kBufferSize))
      return nullptr;
  return buffer_;
}

bool SymbolizerProcess::Restart() {
  if (input_fd_ != kInvalidFd)
    CloseFile(input_fd_);
  if (output_fd_ != kInvalidFd)
    CloseFile(output_fd_);
  return StartSymbolizerSubprocess();
}

SymbolizerProcess::~SymbolizerProcess() {
  std::free(path_);
  if (input_fd_ != kInvalidFd)
    CloseFile(input_fd_);
  if (output_fd_ != kInvalidFd)
    CloseFile(output_fd_);
}

bool SymbolizerProcess::ReadFromSymbolizer(char *buffer, uptr max_length) {
  if (max_length == 0)
    return true;
  uptr read_len = 0;
  while (true) {
    uptr just_read = 0;
    bool success = ReadFromFile(input_fd_, buffer + read_len,
                                max_length - read_len - 1, &just_read, nullptr);
    // We can't read 0 bytes, as we don't expect external symbolizer to close
    // its stdout.
    if (!success || just_read == 0) {
      Report("WARNING: Can't read from symbolizer at fd %zu\n", uptr(input_fd_));
      return false;
    }
    read_len += just_read;
    if (ReachedEndOfOutput(buffer, read_len))
      break;
    if (read_len + 1 == max_length) {
      Report("WARNING: Symbolizer buffer too small\n");
      read_len = 0;
      break;
    }
  }
  buffer[read_len] = '\0';
  return true;
}

bool SymbolizerProcess::WriteToSymbolizer(const char *buffer, uptr length) {
  if (length == 0)
    return true;
  uptr write_len = 0;
  bool success = WriteToFile(output_fd_, buffer, length, &write_len, nullptr);
  if (!success || write_len != length) {
    Report("WARNING: Can't write to symbolizer at fd %zu\n", uptr(input_fd_));
    return false;
  }
  return true;
}
bool LLVMSymbolizer::SymbolizePC(uptr addr, SymbolizedStack *stack) {
  AddressInfo *info = &stack->info;
  const char *buf = FormatAndSendCommand(
      "CODE", info->module, info->module_offset, info->module_arch);
  if (!buf)
    return false;
  ParseSymbolizePCOutput(buf, stack);
  return true;
}


bool LLVMSymbolizer::SymbolizeData(uptr addr, DataInfo *info) {
  const char *buf = FormatAndSendCommand(
      "DATA", info->module, info->module_offset, info->module_arch);
  if (!buf)
    return false;
  ParseSymbolizeDataOutput(buf, info);
  info->start += (addr - info->module_offset); // Add the base address.
  return true;
}

bool LLVMSymbolizer::SymbolizeFrame(uptr addr, FrameInfo *info) {
  const char *buf = FormatAndSendCommand(
      "FRAME", info->module, info->module_offset, info->module_arch);
  if (!buf)
    return false;
  ParseSymbolizeFrameOutput(buf, &info->locals);
  return true;
}

AddressInfo::AddressInfo() {
  std::memset(this, 0, sizeof(AddressInfo));
  function_offset = kUnknown;
}

void AddressInfo::Clear() {
  std::free(module);
  std::free(function);
  std::free(file);
  std::memset(this, 0, sizeof(AddressInfo));
  function_offset = kUnknown;
  uuid_size = 0;
}

void AddressInfo::FillModuleInfo(const char *mod_name, uptr mod_offset,
                                 ModuleArch mod_arch) {
  module = strdup(mod_name);
  module_offset = mod_offset;
  module_arch = mod_arch;
  uuid_size = 0;
}

void AddressInfo::FillModuleInfo(const LoadedModule &mod) {
  module = strdup(mod.full_name());
  module_offset = address - mod.base_address();
  module_arch = mod.arch();
  if (mod.uuid_size())
    std::memcpy(uuid, mod.uuid(), mod.uuid_size());
  uuid_size = mod.uuid_size();
}

SymbolizedStack::SymbolizedStack() : next(nullptr), info() {}

SymbolizedStack *SymbolizedStack::New(uptr addr) {
  SymbolizedStack *res = new SymbolizedStack();
  res->info.address = addr;
  return res;
}

void SymbolizedStack::ClearAll() {
  info.Clear();
  if (next)
    next->ClearAll();
}

DataInfo::DataInfo() {
  std::memset(this, 0, sizeof(DataInfo));
}

void DataInfo::Clear() {
  std::free(module);
  std::free(file);
  std::free(name);
  std::memset(this, 0, sizeof(DataInfo));
}

void FrameInfo::Clear() {
  std::free(module);
  for (LocalInfo &local : locals) {
    std::free(local.function_name);
    std::free(local.name);
    std::free(local.decl_file);
  }
  locals.clear();
}
Symbolizer::Symbolizer(std::vector<SymbolizerTool*> tools)
    : modules_(), tools_(tools) {
  modules_.init();
  RAW_CHECK(modules_.size() > 0);
}
Symbolizer::~Symbolizer() {
  for (auto* tool : tools_) {
      delete tool;
  }
}

bool Symbolizer::SymbolizeData(uptr addr, DataInfo *info) {
  const char *module_name = nullptr;
  uptr module_offset;
  ModuleArch arch;
  if (!FindModuleNameAndOffsetForAddress(addr, &module_name, &module_offset,
                                         &arch))
    return false;
  info->Clear();
  info->module = strdup(module_name);
  info->module_offset = module_offset;
  info->module_arch = arch;
  for (auto &tool : tools_) {
    if (tool->SymbolizeData(addr, info)) {
      return true;
    }
  }
  return true;
}

bool Symbolizer::SymbolizeFrame(uptr addr, FrameInfo *info) {
  const char *module_name = nullptr;
  if (!FindModuleNameAndOffsetForAddress(
          addr, &module_name, &info->module_offset, &info->module_arch))
    return false;
  info->module = strdup(module_name);
  for (auto &tool : tools_) {
    if (tool->SymbolizeFrame(addr, info)) {
      return true;
    }
  }
  return true;
}


bool Symbolizer::FindModuleNameAndOffsetForAddress(uptr address,
                                                   const char **module_name,
                                                   uptr *module_offset,
                                                   ModuleArch *module_arch) {
  const LoadedModule *module = FindModuleForAddress(address);
  if (!module)
    return false;
  *module_name = module->full_name();
  *module_offset = address - module->base_address();
  *module_arch = module->arch();
  return true;
}

static const LoadedModule *SearchForModule(const ListOfModules &modules,
                                           uptr address) {
  for (uptr i = 0; i < modules.size(); i++) {
    if (modules[i].containsAddress(address)) {
      return &modules[i];
    }
  }
  return nullptr;
}

const LoadedModule *Symbolizer::FindModuleForAddress(uptr address) {
  return SearchForModule(modules_, address);
}

void Symbolizer::LateInitialize() {
  Symbolizer::GetOrInit();
}

SymbolizedStack *Symbolizer::SymbolizePC(uptr addr) {
  SymbolizedStack *res = SymbolizedStack::New(addr);
  auto *mod = FindModuleForAddress(addr);
  if (!mod)
    return res;
  // Always fill data about module name and offset.
  res->info.FillModuleInfo(*mod);
  for (auto &tool : tools_) {
    if (tool->SymbolizePC(addr, res)) {
      return res;
    }
  }
  return res;
}

void LoadedModule::set(const char *module_name, uptr base_address) {
  clear();
  full_name_ = strdup(module_name);
  base_address_ = base_address;
}

void LoadedModule::set(const char *module_name, uptr base_address,
                       ModuleArch arch, u8 uuid[kModuleUUIDSize],
                       bool instrumented) {
  set(module_name, base_address);
  arch_ = arch;
  std::memcpy(uuid_, uuid, sizeof(uuid_));
  uuid_size_ = kModuleUUIDSize;
  instrumented_ = instrumented;
}

void LoadedModule::setUuid(const char *uuid, uptr size) {
  if (size > kModuleUUIDSize)
    size = kModuleUUIDSize;
  std::memcpy(uuid_, uuid, size);
  uuid_size_ = size;
}

void LoadedModule::clear() {
  std::free(full_name_);
  base_address_ = 0;
  max_executable_address_ = 0;
  full_name_ = nullptr;
  arch_ = kModuleArchUnknown;
  std::memset(uuid_, 0, kModuleUUIDSize);
  instrumented_ = false;
  ranges_.clear();
}

void LoadedModule::addAddressRange(uptr beg, uptr end, bool executable,
                                   bool writable, const char *name) {
  // ranges_.push_back(AddressRange(beg, end, executable, writable, name));
  ranges_.emplace_back(beg, end, executable, writable, name);
  if (executable && end > max_executable_address_)
    max_executable_address_ = end;
}

bool LoadedModule::containsAddress(uptr address) const {
  for (const AddressRange &r : ranges()) {
    if (r.beg <= address && address < r.end)
      return true;
  }
  return false;
}
}  // namespace llvm_stacktrace
