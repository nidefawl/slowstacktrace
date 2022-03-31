// This file contains modified parts of the LLVM compiler-rt source code
// (c) Michael Hept 2022. See LICENSE.txt
#include "llvm_stacktrace_defs.h"

#if SANITIZER_WINDOWS

#include "llvm_stacktrace.h"

#include "llvm_stacktrace.h"
#include "llvm_symbolizer.h"
#include "llvm_symbolizer_internal.h"


#define WIN32_LEAN_AND_MEAN
#define NOGDI

#include <windows.h>
#include <dbghelp.h>
#include <psapi.h>

namespace llvm_stacktrace {

char **GetArgv() {
  // FIXME: Actually implement this function.
  return 0;
}

char **GetEnviron() {
  // FIXME: Actually implement this function.
  return 0;
}

void CloseFile(fd_t fd) {
  CloseHandle(fd);
}

bool ReadFromFile(fd_t fd, void *buff, uptr buff_size, uptr *bytes_read, error_t *error_p) {
  CHECK(fd != kInvalidFd);

  // bytes_read can't be passed directly to ReadFile:
  // uptr is unsigned long long on 64-bit Windows.
  unsigned long num_read_long;

  bool success = ::ReadFile(fd, buff, buff_size, &num_read_long, nullptr);
  if (!success && error_p)
    *error_p = GetLastError();
  if (bytes_read)
    *bytes_read = num_read_long;
  return success;
}

bool WriteToFile(fd_t fd, const void *buff, uptr buff_size, uptr *bytes_written,
                 error_t *error_p) {
  CHECK(fd != kInvalidFd);

  // Handle null optional parameters.
  error_t dummy_error;
  error_p = error_p ? error_p : &dummy_error;
  uptr dummy_bytes_written;
  bytes_written = bytes_written ? bytes_written : &dummy_bytes_written;

  // Initialize output parameters in case we fail.
  *error_p = 0;
  *bytes_written = 0;

  // Map the conventional Unix fds 1 and 2 to Windows handles. They might be
  // closed, in which case this will fail.
  if (fd == kStdoutFd || fd == kStderrFd) {
    fd = GetStdHandle(fd == kStdoutFd ? STD_OUTPUT_HANDLE : STD_ERROR_HANDLE);
    if (fd == 0) {
      *error_p = ERROR_INVALID_HANDLE;
      return false;
    }
  }

  DWORD bytes_written_32;
  if (!WriteFile(fd, buff, buff_size, &bytes_written_32, 0)) {
    *error_p = GetLastError();
    return false;
  } else {
    *bytes_written = bytes_written_32;
    return true;
  }
}

bool FileExists(const char *filename) {
  return ::GetFileAttributesA(filename) != INVALID_FILE_ATTRIBUTES;
}

bool DirExists(const char *path) {
  auto attr = ::GetFileAttributesA(path);
  return (attr != INVALID_FILE_ATTRIBUTES) && (attr & FILE_ATTRIBUTE_DIRECTORY);
}


enum FileAccessMode {
  RdOnly,
  WrOnly
};
// ------------------ sanitizer_libc.h
fd_t OpenFile(const char *filename, FileAccessMode mode, error_t *last_error) {
  // FIXME: Use the wide variants to handle Unicode filenames.
  fd_t res;
  if (mode == RdOnly) {
    res = CreateFileA(filename, GENERIC_READ,
                      FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                      nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
  } else if (mode == WrOnly) {
    res = CreateFileA(filename, GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS,
                      FILE_ATTRIBUTE_NORMAL, nullptr);
  } else {
    return kInvalidFd;
  }
  CHECK(res != kStdoutFd || kStdoutFd == kInvalidFd);
  CHECK(res != kStderrFd || kStderrFd == kInvalidFd);
  if (res == kInvalidFd && last_error)
    *last_error = GetLastError();
  return res;
}

#if !SANITIZER_GO

// Scoped file handle closer.
struct FileCloser {
  explicit FileCloser(fd_t fd) : fd(fd) {}
  ~FileCloser() { CloseFile(fd); }
  fd_t fd;
};
// Read the file to extract the ImageBase field from the PE header. If ASLR is
// disabled and this virtual address is available, the loader will typically
// load the image at this address. Therefore, we call it the preferred base. Any
// addresses in the DWARF typically assume that the object has been loaded at
// this address.
static uptr GetPreferredBase(const char *modname, char *buf, size_t buf_size) {
  fd_t fd = OpenFile(modname, RdOnly, nullptr);
  if (fd == kInvalidFd)
    return 0;
  FileCloser closer(fd);

  // Read just the DOS header.
  IMAGE_DOS_HEADER dos_header;
  uptr bytes_read;
  if (!ReadFromFile(fd, &dos_header, sizeof(dos_header), &bytes_read, nullptr) ||
      bytes_read != sizeof(dos_header))
    return 0;

  // The file should start with the right signature.
  if (dos_header.e_magic != IMAGE_DOS_SIGNATURE)
    return 0;

  // The layout at e_lfanew is:
  // "PE\0\0"
  // IMAGE_FILE_HEADER
  // IMAGE_OPTIONAL_HEADER
  // Seek to e_lfanew and read all that data.
  if (::SetFilePointer(fd, dos_header.e_lfanew, nullptr, FILE_BEGIN) ==
      INVALID_SET_FILE_POINTER)
    return 0;
  if (!ReadFromFile(fd, buf, buf_size, &bytes_read, nullptr) || bytes_read != buf_size)
    return 0;

  // Check for "PE\0\0" before the PE header.
  char *pe_sig = &buf[0];
  if (std::memcmp(pe_sig, "PE\0\0", 4) != 0)
    return 0;

  // Skip over IMAGE_FILE_HEADER. We could do more validation here if we wanted.
  IMAGE_OPTIONAL_HEADER *pe_header =
      (IMAGE_OPTIONAL_HEADER *)(pe_sig + 4 + sizeof(IMAGE_FILE_HEADER));

  // Check for more magic in the PE header.
  if (pe_header->Magic != IMAGE_NT_OPTIONAL_HDR_MAGIC)
    return 0;

  // Finally, return the ImageBase.
  return (uptr)pe_header->ImageBase;
}

void ListOfModules::init() {
  clearOrInit();
  HANDLE cur_process = GetCurrentProcess();

  // Query the list of modules.  Start by assuming there are no more than 256
  // modules and retry if that's not sufficient.
  HMODULE *hmodules = 0;
  uptr modules_buffer_size = sizeof(HMODULE) * 256;
  DWORD bytes_required;
  while (!hmodules) {
    hmodules = (HMODULE *)std::malloc(modules_buffer_size);
    CHECK(EnumProcessModules(cur_process, hmodules, modules_buffer_size, &bytes_required));
    if (bytes_required > modules_buffer_size) {
      // Either there turned out to be more than 256 hmodules, or new hmodules
      // could have loaded since the last try.  Retry.
      std::free(hmodules);
      hmodules = 0;
      modules_buffer_size = bytes_required;
    }
  }

  std::vector<char> buf(4 + sizeof(IMAGE_FILE_HEADER) +
                               sizeof(IMAGE_OPTIONAL_HEADER));
  std::vector<wchar_t> modname_utf16(kMaxPathLength);
  std::vector<char> module_name(kMaxPathLength);
  // |num_modules| is the number of modules actually present,
  size_t num_modules = bytes_required / sizeof(HMODULE);
  for (size_t i = 0; i < num_modules; ++i) {
    HMODULE handle = hmodules[i];
    MODULEINFO mi;
    if (!GetModuleInformation(cur_process, handle, &mi, sizeof(mi)))
      continue;

    // Get the UTF-16 path and convert to UTF-8.
    int modname_utf16_len =
        GetModuleFileNameW(handle, &modname_utf16[0], kMaxPathLength);
    if (modname_utf16_len == 0)
      modname_utf16[0] = '\0';
    int module_name_len = ::WideCharToMultiByte(
        CP_UTF8, 0, &modname_utf16[0], modname_utf16_len + 1, &module_name[0],
        kMaxPathLength, NULL, NULL);
    module_name[module_name_len] = '\0';

    uptr base_address = (uptr)mi.lpBaseOfDll;
    uptr end_address = (uptr)mi.lpBaseOfDll + mi.SizeOfImage;

    // Adjust the base address of the module so that we get a VA instead of an
    // RVA when computing the module offset. This helps llvm-symbolizer find the
    // right DWARF CU. In the common case that the image is loaded at it's
    // preferred address, we will now print normal virtual addresses.
    uptr preferred_base =
        GetPreferredBase(&module_name[0], &buf[0], buf.size());
    uptr adjusted_base = base_address - preferred_base;

    modules_.push_back(LoadedModule());
    LoadedModule &cur_module = modules_.back();
    cur_module.set(&module_name[0], adjusted_base);
    // We add the whole module as one single address range.
    cur_module.addAddressRange(base_address, end_address, /*executable*/ true,
                               /*writable*/ true);
  }
  std::free(hmodules);
}
#endif // SANITIZER_GO

decltype(::StackWalk64) *StackWalk64;
decltype(::SymCleanup) *SymCleanup;
decltype(::SymFromAddr) *SymFromAddr;
// decltype(::SymFunctionTableAccess64) *SymFunctionTableAccess64;
decltype(::SymGetLineFromAddr64) *SymGetLineFromAddr64;
// decltype(::SymGetModuleBase64) *SymGetModuleBase64;
decltype(::SymGetSearchPathW) *SymGetSearchPathW;
decltype(::SymInitialize) *SymInitialize;
decltype(::SymSetOptions) *SymSetOptions;
decltype(::SymSetSearchPathW) *SymSetSearchPathW;
// decltype(::UnDecorateSymbolName) *UnDecorateSymbolName;

namespace {

class WinSymbolizerTool final : public SymbolizerTool {
 public:
  // The constructor is provided to avoid synthesized memsets.
  WinSymbolizerTool() {}

  bool SymbolizePC(uptr addr, SymbolizedStack *stack) override;
  bool SymbolizeData(uptr addr, DataInfo *info) override {
    return false;
  }
};

bool is_dbghelp_initialized = false;

bool TrySymInitialize() {
  SymSetOptions(SYMOPT_DEFERRED_LOADS | SYMOPT_UNDNAME | SYMOPT_LOAD_LINES);
  return SymInitialize(GetCurrentProcess(), 0, TRUE);
  // FIXME: We don't call SymCleanup() on exit yet - should we?
}

}  // namespace

// Initializes DbgHelp library, if it's not yet initialized. Calls to this
// function should be synchronized with respect to other calls to DbgHelp API
// (e.g. from WinSymbolizerTool).
void InitializeDbgHelpIfNeeded() {
  if (is_dbghelp_initialized)
    return;

  HMODULE dbghelp = LoadLibraryA("dbghelp.dll");
  CHECK(dbghelp && "failed to load dbghelp.dll");

#define DBGHELP_IMPORT(name)                                                  \
  do {                                                                        \
    name =                                                                    \
        reinterpret_cast<decltype(::name) *>(GetProcAddress(dbghelp, #name)); \
    CHECK(name != nullptr);                                                   \
  } while (0)
  DBGHELP_IMPORT(StackWalk64);
  DBGHELP_IMPORT(SymCleanup);
  DBGHELP_IMPORT(SymFromAddr);
  // DBGHELP_IMPORT(SymFunctionTableAccess64);
  DBGHELP_IMPORT(SymGetLineFromAddr64);
  // DBGHELP_IMPORT(SymGetModuleBase64);
  DBGHELP_IMPORT(SymGetSearchPathW);
  DBGHELP_IMPORT(SymInitialize);
  DBGHELP_IMPORT(SymSetOptions);
  DBGHELP_IMPORT(SymSetSearchPathW);
  // DBGHELP_IMPORT(UnDecorateSymbolName);
#undef DBGHELP_IMPORT

  if (!TrySymInitialize()) {
    // OK, maybe the client app has called SymInitialize already.
    // That's a bit unfortunate for us as all the DbgHelp functions are
    // single-threaded and we can't coordinate with the app.
    // FIXME: Can we stop the other threads at this point?
    // Anyways, we have to reconfigure stuff to make sure that SymInitialize
    // has all the appropriate options set.
    // Cross our fingers and reinitialize DbgHelp.
    Report("*** WARNING: Failed to initialize DbgHelp!              ***\n");
    Report("*** Most likely this means that the app is already      ***\n");
    Report("*** using DbgHelp, possibly with incompatible flags.    ***\n");
    Report("*** Due to technical reasons, symbolization might crash ***\n");
    Report("*** or produce wrong results.                           ***\n");
    SymCleanup(GetCurrentProcess());
    TrySymInitialize();
  }
  is_dbghelp_initialized = true;

  // When an executable is run from a location different from the one where it
  // was originally built, we may not see the nearby PDB files.
  // To work around this, let's append the directory of the main module
  // to the symbol search path.  All the failures below are not fatal.
  const size_t kSymPathSize = 2048;
  static wchar_t path_buffer[kSymPathSize + 1 + MAX_PATH];
  if (!SymGetSearchPathW(GetCurrentProcess(), path_buffer, kSymPathSize)) {
    Report("*** WARNING: Failed to SymGetSearchPathW ***\n");
    return;
  }
  size_t sz = wcslen(path_buffer);
  if (sz) {
    CHECK_EQ(0, wcscat_s(path_buffer, L";"));
    sz++;
  }
  DWORD res = GetModuleFileNameW(NULL, path_buffer + sz, MAX_PATH);
  if (res == 0 || res == MAX_PATH) {
    Report("*** WARNING: Failed to getting the EXE directory ***\n");
    return;
  }
  // Write the zero character in place of the last backslash to get the
  // directory of the main module at the end of path_buffer.
  wchar_t *last_bslash = wcsrchr(path_buffer + sz, L'\\');
  CHECK_NE(last_bslash, 0);
  *last_bslash = L'\0';
  if (!SymSetSearchPathW(GetCurrentProcess(), path_buffer)) {
    Report("*** WARNING: Failed to SymSetSearchPathW\n");
    return;
  }
}

bool WinSymbolizerTool::SymbolizePC(uptr addr, SymbolizedStack *frame) {
  InitializeDbgHelpIfNeeded();

  // See https://docs.microsoft.com/en-us/windows/win32/debug/retrieving-symbol-information-by-address
  std::vector<char> buffer(sizeof(SYMBOL_INFO) +
                                  MAX_SYM_NAME * sizeof(CHAR));
  PSYMBOL_INFO symbol = (PSYMBOL_INFO)&buffer[0];
  symbol->SizeOfStruct = sizeof(SYMBOL_INFO);
  symbol->MaxNameLen = MAX_SYM_NAME;
  DWORD64 offset = 0;
  BOOL got_objname = SymFromAddr(GetCurrentProcess(),
                                 (DWORD64)addr, &offset, symbol);
  if (!got_objname)
    return false;

  DWORD unused;
  IMAGEHLP_LINE64 line_info;
  line_info.SizeOfStruct = sizeof(IMAGEHLP_LINE64);
  BOOL got_fileline = SymGetLineFromAddr64(GetCurrentProcess(), (DWORD64)addr,
                                           &unused, &line_info);
  frame->info.function = strdup(symbol->Name);
  frame->info.function_offset = (uptr)offset;
  if (got_fileline) {
    frame->info.file = strdup(line_info.FileName);
    frame->info.line = line_info.LineNumber;
  }
  // Only consider this a successful symbolization attempt if we got file info.
  // Otherwise, try llvm-symbolizer.
  return got_fileline;
}

namespace {
struct ScopedHandle {
  ScopedHandle() : h_(nullptr) {}
  explicit ScopedHandle(HANDLE h) : h_(h) {}
  ~ScopedHandle() {
    if (h_)
      ::CloseHandle(h_);
  }
  HANDLE get() { return h_; }
  HANDLE *receive() { return &h_; }
  HANDLE release() {
    HANDLE h = h_;
    h_ = nullptr;
    return h;
  }
  HANDLE h_;
};
} // namespace

bool SymbolizerProcess::StartSymbolizerSubprocess() {
  // Create inherited pipes for stdin and stdout.
  ScopedHandle stdin_read, stdin_write;
  ScopedHandle stdout_read, stdout_write;
  SECURITY_ATTRIBUTES attrs;
  attrs.nLength = sizeof(SECURITY_ATTRIBUTES);
  attrs.bInheritHandle = TRUE;
  attrs.lpSecurityDescriptor = nullptr;
  if (!::CreatePipe(stdin_read.receive(), stdin_write.receive(), &attrs, 0) ||
      !::CreatePipe(stdout_read.receive(), stdout_write.receive(), &attrs, 0)) {
    VReport(2, "WARNING: llvm_stacktrace CreatePipe failed (error code: %lu)\n", GetLastError());
    return false;
  }

  // Don't inherit the writing end of stdin or the reading end of stdout.
  if (!SetHandleInformation(stdin_write.get(), HANDLE_FLAG_INHERIT, 0) ||
      !SetHandleInformation(stdout_read.get(), HANDLE_FLAG_INHERIT, 0)) {
    VReport(2, "WARNING: llvm_stacktrace SetHandleInformation failed (error code: %lu)\n", GetLastError());
    return false;
  }

  // Compute the command line. Wrap double quotes around everything.
  const char *argv[kArgVMax];
  GetArgV(path_, argv);
  InternalScopedString command_line;
  for (int i = 0; argv[i]; i++) {
    const char *arg = argv[i];
    int arglen = std::strlen(arg);
    // Check that tool command lines are simple and that complete escaping is
    // unnecessary.
    CHECK(!std::strchr(arg, '"') && "quotes in args unsupported");
    CHECK(!std::strstr(arg, "\\\\") &&
          "double backslashes in args unsupported");
    CHECK(arglen > 0 && arg[arglen - 1] != '\\' &&
          "args ending in backslash and empty args unsupported");
    command_line.append("\"%s\" ", arg);
  }
  VReport(3, "Launching symbolizer command: %s\n", command_line.data());

  // Launch llvm-symbolizer with stdin and stdout redirected.
  STARTUPINFOA si;
  memset(&si, 0, sizeof(si));
  si.cb = sizeof(si);
  si.dwFlags |= STARTF_USESTDHANDLES;
  si.hStdInput = stdin_read.get();
  si.hStdOutput = stdout_write.get();
  PROCESS_INFORMATION pi;
  memset(&pi, 0, sizeof(pi));
  if (!CreateProcessA(path_,               // Executable
                      command_line.data(), // Command line
                      nullptr,             // Process handle not inheritable
                      nullptr,             // Thread handle not inheritable
                      TRUE,                // Set handle inheritance to TRUE
                      0,                   // Creation flags
                      nullptr,             // Use parent's environment block
                      nullptr,             // Use parent's starting directory
                      &si, &pi)) {
    VReport(2, "WARNING: llvm_stacktrace failed to create process for %s (error code: %lu)\n", path_, GetLastError());
    return false;
  }

  // Process creation succeeded, so transfer handle ownership into the fields.
  input_fd_ = stdout_read.release();
  output_fd_ = stdin_write.release();

  // The llvm-symbolizer process is responsible for quitting itself when the
  // stdin pipe is closed, so we don't need these handles. Close them to prevent
  // leaks. If we ever want to try to kill the symbolizer process from the
  // parent, we'll want to hang on to these handles.
  CloseHandle(pi.hProcess);
  CloseHandle(pi.hThread);
  return true;
}

static void ChooseSymbolizerTools(std::vector<SymbolizerTool*> *list) {

  // Add llvm-symbolizer.
  InternalScopedString binary_path;
  if (FindPathToBinary("llvm-symbolizer.exe", binary_path)) {
    VReport(2, "Using llvm-symbolizer at %s\n",binary_path.data());
    list->push_back(new LLVMSymbolizer(binary_path.data()));
  } else {
    VReport(2, "External symbolizer is not present.\n");
  }

  // Add the dbghelp based symbolizer.
  list->push_back(new WinSymbolizerTool());
}

Symbolizer *Symbolizer::PlatformInit() {
  std::vector<SymbolizerTool*> list;
  list.clear();
  ChooseSymbolizerTools(&list);

  return new Symbolizer(list);
}

}  // namespace llvm_stacktrace

#endif  // SANITIZER_WINDOWS
