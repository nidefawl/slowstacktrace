// This file contains modified parts of the LLVM compiler-rt source code
// (c) Michael Hept 2022. See LICENSE.txt
#include "llvm_stacktrace_defs.h"

#if SANITIZER_POSIX
#include "llvm_stacktrace.h"
#include "llvm_string.h"
#include "llvm_symbolizer.h"
#include "llvm_symbolizer_internal.h"

#include <dlfcn.h>   // for dlsym()
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <link.h>
#include <pthread.h>
#include <time.h>
// #include <sched.h>
// #include <signal.h>
#include <sys/wait.h>
// #include <sys/param.h>

// #include <sys/resource.h>
#include <sys/stat.h>
// #include <sys/types.h>
// #include <ucontext.h>

#if SANITIZER_LINUX
#include <sys/utsname.h>
#endif

#if SANITIZER_LINUX && !SANITIZER_ANDROID
#include <sys/personality.h>
#endif

#include <cstdio>
#include <cstdlib>

namespace llvm_stacktrace {

void CloseFile(fd_t fd) {
  close(fd);
}

bool internal_iserror(uptr retval, int *rverrno) {
  if (retval >= (uptr)-4095) {
    if (rverrno)
      *rverrno = -retval;
    return true;
  }
  return false;
}

bool ReadFromFile(fd_t fd, void *buff, uptr buff_size, uptr *bytes_read,
                  error_t *error_p) {
  uptr res = read(fd, buff, buff_size);
  if (internal_iserror(res, error_p))
    return false;
  if (bytes_read)
    *bytes_read = res;
  return true;
}

bool WriteToFile(fd_t fd, const void *buff, uptr buff_size, uptr *bytes_written,
                 error_t *error_p) {
  uptr res = write(fd, buff, buff_size);
  if (internal_iserror(res, error_p))
    return false;
  if (bytes_written)
    *bytes_written = res;
  return true;
}

#if !SANITIZER_FREEBSD && !SANITIZER_NETBSD && !SANITIZER_GO
extern "C" {
SANITIZER_WEAK_ATTRIBUTE extern void *__libc_stack_end;
}
#endif

static void GetArgsAndEnv(char ***argv, char ***envp) {
#if SANITIZER_FREEBSD
  // On FreeBSD, retrieving the argument and environment arrays is done via the
  // kern.ps_strings sysctl, which returns a pointer to a structure containing
  // this information. See also <sys/exec.h>.
  ps_strings *pss;
  uptr sz = sizeof(pss);
  if (internal_sysctlbyname("kern.ps_strings", &pss, &sz, NULL, 0) == -1) {
    Printf("sysctl kern.ps_strings failed\n");
    Die();
  }
  *argv = pss->ps_argvstr;
  *envp = pss->ps_envstr;
#elif SANITIZER_NETBSD
  *argv = __ps_strings->ps_argvstr;
  *envp = __ps_strings->ps_envstr;
#else // SANITIZER_FREEBSD
#if !SANITIZER_GO
  if (&__libc_stack_end) {
    uptr* stack_end = (uptr*)__libc_stack_end;
    // Normally argc can be obtained from *stack_end, however, on ARM glibc's
    // _start clobbers it:
    // https://sourceware.org/git/?p=glibc.git;a=blob;f=sysdeps/arm/start.S;hb=refs/heads/release/2.31/master#l75
    // Do not special-case ARM and infer argc from argv everywhere.
    int argc = 0;
    while (stack_end[argc + 1]) argc++;
    *argv = (char**)(stack_end + 1);
    *envp = (char**)(stack_end + argc + 2);
  } else {
    *argv = nullptr;
    *envp = nullptr;
// #endif // !SANITIZER_GO
//     static const int kMaxArgv = 2000, kMaxEnvp = 2000;
//     ReadNullSepFileToArray("/proc/self/cmdline", argv, kMaxArgv);
//     ReadNullSepFileToArray("/proc/self/environ", envp, kMaxEnvp);
// #if !SANITIZER_GO
  }
#endif // !SANITIZER_GO
#endif // SANITIZER_FREEBSD
}

char **GetArgv() {
  char **argv, **envp;
  GetArgsAndEnv(&argv, &envp);
  return argv;
}

char **GetEnviron() {
  char **argv, **envp;
  GetArgsAndEnv(&argv, &envp);
  return envp;
}

// ----------------- sanitizer_common.h
bool FileExists(const char *filename) {
  struct stat64 st;
  if (stat64(filename, &st)) {
    return false;
  }
  // Sanity check: filename is a regular file.
  return S_ISREG(st.st_mode);
}
bool DirExists(const char *path) {
  struct stat64 st;
  if (stat64(path, &st)) {
    return false;
  }
  // Sanity check: filename is a regular file.
  return S_ISDIR(st.st_mode);
}


uptr ReadBinaryName(/*out*/char *buf, uptr buf_len) {
#if SANITIZER_SOLARIS
  const char *default_module_name = getexecname();
  CHECK_NE(default_module_name, NULL);
  return snprintf(buf, buf_len, "%s", default_module_name);
#else
#if SANITIZER_FREEBSD || SANITIZER_NETBSD
#if SANITIZER_FREEBSD
  const int Mib[4] = {CTL_KERN, KERN_PROC, KERN_PROC_PATHNAME, -1};
#else
  const int Mib[4] = {CTL_KERN, KERN_PROC_ARGS, -1, KERN_PROC_PATHNAME};
#endif
  const char *default_module_name = "kern.proc.pathname";
  uptr Size = buf_len;
  bool IsErr =
      (internal_sysctl(Mib, ARRAY_SIZE(Mib), buf, &Size, NULL, 0) != 0);
  int readlink_error = IsErr ? errno : 0;
  uptr module_name_len = Size;
#else
  const char *default_module_name = "/proc/self/exe";
  uptr module_name_len = readlink(
      default_module_name, buf, buf_len);
  int readlink_error;
  bool IsErr = internal_iserror(module_name_len, &readlink_error);
#endif  // SANITIZER_SOLARIS
  if (IsErr) {
    // We can't read binary name for some reason, assume it's unknown.
    Report("WARNING: reading executable name failed with errno %d, "
           "some stack frames may not be symbolized\n", readlink_error);
    module_name_len = snprintf(buf, buf_len, "%s",
                                        default_module_name);
    CHECK_LT(module_name_len, buf_len);
  }
  return module_name_len;
#endif
}

#if 0
static uptr ReadProcessName(/*out*/ char *buf, uptr buf_len) {
  ReadBinaryName(buf, buf_len);
  char *s = const_cast<char *>(StripModuleName(buf));
  uptr len = std::strlen(s);
  if (s != buf) {
    std::memmove(buf, s, len);
    buf[len] = '\0';
  }
  return len;
}

static uptr ReadBinaryDir(/*out*/ char *buf, uptr buf_len) {
  ReadBinaryName(buf, buf_len);
  const char *exec_name_pos = StripModuleName(buf);
  uptr name_len = exec_name_pos - buf;
  buf[name_len] = '\0';
  return name_len;
}
#endif

#if !SANITIZER_FREEBSD
typedef ElfW(Phdr) Elf_Phdr;
#elif SANITIZER_WORDSIZE == 32 && __FreeBSD_version <= 902001  // v9.2
#define Elf_Phdr XElf32_Phdr
#define dl_phdr_info xdl_phdr_info
#define dl_iterate_phdr(c, b) xdl_iterate_phdr((c), (b))
#endif  // !SANITIZER_FREEBSD

struct DlIteratePhdrData {
  std::vector<LoadedModule> *modules;
  bool first;
};

static int AddModuleSegments(const char *module_name, dl_phdr_info *info,
                             std::vector<LoadedModule> *modules) {
  if (module_name[0] == '\0')
    return 0;
  LoadedModule cur_module;
  cur_module.set(module_name, info->dlpi_addr);
  for (int i = 0; i < (int)info->dlpi_phnum; i++) {
    const Elf_Phdr *phdr = &info->dlpi_phdr[i];
    if (phdr->p_type == PT_LOAD) {
      uptr cur_beg = info->dlpi_addr + phdr->p_vaddr;
      uptr cur_end = cur_beg + phdr->p_memsz;
      bool executable = phdr->p_flags & PF_X;
      bool writable = phdr->p_flags & PF_W;
      cur_module.addAddressRange(cur_beg, cur_end, executable,
                                 writable);
    } else if (phdr->p_type == PT_NOTE) {
#  ifdef NT_GNU_BUILD_ID
      uptr off = 0;
      while (off + sizeof(ElfW(Nhdr)) < phdr->p_memsz) {
        auto *nhdr = reinterpret_cast<const ElfW(Nhdr) *>(info->dlpi_addr +
                                                          phdr->p_vaddr + off);
        constexpr auto kGnuNamesz = 4;  // "GNU" with NUL-byte.
        static_assert(kGnuNamesz % 4 == 0, "kGnuNameSize is aligned to 4.");
        if (nhdr->n_type == NT_GNU_BUILD_ID && nhdr->n_namesz == kGnuNamesz) {
          if (off + sizeof(ElfW(Nhdr)) + nhdr->n_namesz + nhdr->n_descsz >
              phdr->p_memsz) {
            // Something is very wrong, bail out instead of reading potentially
            // arbitrary memory.
            break;
          }
          const char *name =
              reinterpret_cast<const char *>(nhdr) + sizeof(*nhdr);
          if (std::memcmp(name, "GNU", 3) == 0) {
            const char *value = reinterpret_cast<const char *>(nhdr) +
                                sizeof(*nhdr) + kGnuNamesz;
            cur_module.setUuid(value, nhdr->n_descsz);
            break;
          }
        }
        off += sizeof(*nhdr) + RoundUpTo(nhdr->n_namesz, 4) +
               RoundUpTo(nhdr->n_descsz, 4);
      }
#  endif
    }
  }
  modules->push_back(cur_module);
  return 0;
}

static int dl_iterate_phdr_cb(dl_phdr_info *info, size_t size, void *arg) {
  DlIteratePhdrData *data = (DlIteratePhdrData *)arg;
  if (data->first) {
    std::vector<char> module_name(kMaxPathLength);
    data->first = false;
    // First module is the binary itself.
    ReadBinaryName(module_name.data(), module_name.size());
    return AddModuleSegments(module_name.data(), info, data->modules);
  }

  if (info->dlpi_name) {
    InternalScopedString module_name;
    module_name.append("%s", info->dlpi_name);
    return AddModuleSegments(module_name.data(), info, data->modules);
  }

  return 0;
}

void ListOfModules::init() {
  clearOrInit();
  DlIteratePhdrData data = {&modules_, true};
  dl_iterate_phdr(dl_iterate_phdr_cb, &data);
}

static bool CreateTwoHighNumberedPipes(int *infd_, int *outfd_) {
  int *infd = NULL;
  int *outfd = NULL;
  // The client program may close its stdin and/or stdout and/or stderr
  // thus allowing socketpair to reuse file descriptors 0, 1 or 2.
  // In this case the communication between the forked processes may be
  // broken if either the parent or the child tries to close or duplicate
  // these descriptors. The loop below produces two pairs of file
  // descriptors, each greater than 2 (stderr).
  int sock_pair[5][2];
  for (int i = 0; i < 5; i++) {
    if (pipe(sock_pair[i]) == -1) {
      for (int j = 0; j < i; j++) {
        close(sock_pair[j][0]);
        close(sock_pair[j][1]);
      }
      return false;
    } else if (sock_pair[i][0] > 2 && sock_pair[i][1] > 2) {
      if (infd == NULL) {
        infd = sock_pair[i];
      } else {
        outfd = sock_pair[i];
        for (int j = 0; j < i; j++) {
          if (sock_pair[j] == infd) continue;
          close(sock_pair[j][0]);
          close(sock_pair[j][1]);
        }
        break;
      }
    }
  }
  CHECK(infd);
  CHECK(outfd);
  infd_[0] = infd[0];
  infd_[1] = infd[1];
  outfd_[0] = outfd[0];
  outfd_[1] = outfd[1];
  return true;
}
namespace {
  

bool IsProcessRunning(pid_t pid) {
  int process_status;
  uptr waitpid_status = wait4(pid, &process_status, WNOHANG, nullptr);
  int local_errno;
  if (internal_iserror(waitpid_status, &local_errno)) {
    VReport(1, "Waiting on the process failed (errno %d).\n", local_errno);
    return false;
  }
  return waitpid_status == 0;
}
template <typename Fn>
class RunOnDestruction {
 public:
  explicit RunOnDestruction(Fn fn) : fn_(fn) {}
  ~RunOnDestruction() { fn_(); }

 private:
  Fn fn_;
};

// A simple scope guard. Usage:
// auto cleanup = at_scope_exit([]{ do_cleanup; });
template <typename Fn>
RunOnDestruction<Fn> at_scope_exit(Fn fn) {
  return RunOnDestruction<Fn>(fn);
}

pid_t StartSubprocess(const char *program, const char *const argv[],
                      const char *const envp[], fd_t stdin_fd, fd_t stdout_fd,
                      fd_t stderr_fd) {
  auto file_closer = at_scope_exit([&] {
    if (stdin_fd != kInvalidFd) {
      close(stdin_fd);
    }
    if (stdout_fd != kInvalidFd) {
      close(stdout_fd);
    }
    if (stderr_fd != kInvalidFd) {
      close(stderr_fd);
    }
  });

  int pid = fork();

  if (pid < 0) {
    int rverrno;
    if (internal_iserror(pid, &rverrno)) {
      Report("WARNING: failed to fork (errno %d)\n", rverrno);
    }
    return pid;
  }

  if (pid == 0) {
    // Child subprocess
    if (stdin_fd != kInvalidFd) {
      close(STDIN_FILENO);
      dup2(stdin_fd, STDIN_FILENO);
      close(stdin_fd);
    }
    if (stdout_fd != kInvalidFd) {
      close(STDOUT_FILENO);
      dup2(stdout_fd, STDOUT_FILENO);
      close(stdout_fd);
    }
    if (stderr_fd != kInvalidFd) {
      close(STDERR_FILENO);
      dup2(stderr_fd, STDERR_FILENO);
      close(stderr_fd);
    }

    for (int fd = sysconf(_SC_OPEN_MAX); fd > 2; fd--) close(fd);

    execve(program, const_cast<char **>(&argv[0]),
                    const_cast<char *const *>(envp));
    exit(1);
  }

  return pid;
}
}
bool SymbolizerProcess::StartSymbolizerSubprocess() {
  if (!FileExists(path_)) {
    if (!reported_invalid_path_) {
      Report("WARNING: invalid path to external symbolizer!\n");
      reported_invalid_path_ = true;
    }
    return false;
  }

  const char *argv[kArgVMax];
  GetArgV(path_, argv);
  pid_t pid;

  // Report how symbolizer is being launched for debugging purposes.
  // if (Verbosity() >= 3) 
  {
    // Only use `Report` for first line so subsequent prints don't get prefixed
    // with current PID.
    Report("Launching Symbolizer process: ");
    for (unsigned index = 0; index < kArgVMax && argv[index]; ++index)
      Printf("%s ", argv[index]);
    Printf("\n");
  }

  if (use_posix_spawn_) {
#if SANITIZER_MAC
    fd_t fd = internal_spawn(argv, const_cast<const char **>(GetEnvP()), &pid);
    if (fd == kInvalidFd) {
      Report("WARNING: failed to spawn external symbolizer (errno: %d)\n",
             errno);
      return false;
    }

    input_fd_ = fd;
    output_fd_ = fd;
#else  // SANITIZER_MAC
    UNIMPLEMENTED();
#endif  // SANITIZER_MAC
  } else {
    fd_t infd[2] = {}, outfd[2] = {};
    if (!CreateTwoHighNumberedPipes(infd, outfd)) {
      Report("WARNING: Can't create a socket pair to start "
             "external symbolizer (errno: %d)\n", errno);
      return false;
    }

    pid = StartSubprocess(path_, argv, GetEnvP(), /* stdin */ outfd[0],
                          /* stdout */ infd[1], kInvalidFd);
    if (pid < 0) {
      close(infd[0]);
      close(outfd[1]);
      return false;
    }

    input_fd_ = infd[0];
    output_fd_ = outfd[1];
  }

  CHECK_GT(pid, 0);

  // Check that symbolizer subprocess started successfully.
  // SleepForMillis(kSymbolizerStartupTimeMillis);
  u64 useconds = kSymbolizerStartupTimeMillis * 1000;
  struct timespec ts;
  ts.tv_sec = useconds / 1000000;
  ts.tv_nsec = (useconds % 1000000) * 1000;
  nanosleep(&ts, &ts);
  if (!IsProcessRunning(pid)) {
    // Either waitpid failed, or child has already exited.
    Report("WARNING: external symbolizer didn't start up correctly!\n");
    return false;
  }

  return true;
}


static SymbolizerTool *ChooseExternalSymbolizer() {
  InternalScopedString binary_path;
  if (FindPathToBinary("llvm-symbolizer", binary_path)) {
    VReport(2, "Using llvm-symbolizer found at: %s\n", binary_path.data());
    return new LLVMSymbolizer(binary_path.data());
  }
  return nullptr;
}

static void ChooseSymbolizerTools(std::vector<SymbolizerTool*> *list) {
  if (SymbolizerTool *tool = ChooseExternalSymbolizer()) {
    list->push_back(tool);
  }

#if SANITIZER_MAC
  VReport(2, "Using dladdr symbolizer.\n");
  list->push_back(new(*allocator) DlAddrSymbolizer());
#endif  // SANITIZER_MAC
}

Symbolizer *Symbolizer::PlatformInit() {
  std::vector<SymbolizerTool*> list;
  list.clear();
  ChooseSymbolizerTools(&list);
  return new Symbolizer(list);
}


}  // namespace llvm_stacktrace

#endif  // SANITIZER_POSIX
