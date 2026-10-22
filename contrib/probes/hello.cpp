// SPDX-License-Identifier: CC0-1.0

#if defined(_WIN32)
#include <windows.h>
#elif defined(__APPLE__)
#include <dispatch/dispatch.h>
#include <mach/mach.h>
#include <unistd.h>
#elif defined(__linux__)
#include <linux/version.h>
#include <sys/syscall.h>
#include <unistd.h>
#else
#error "no system interface is known for this target"
#endif

#include <string>

namespace {

#if defined(_WIN32)
bool say(const std::string& text)
{
  HANDLE out = GetStdHandle(STD_OUTPUT_HANDLE);
  DWORD written = 0;
  const auto length = static_cast<DWORD>(text.size());
  return out != INVALID_HANDLE_VALUE && WriteFile(out, text.data(), length, &written, nullptr) && written == length;
}
#elif defined(__APPLE__)
bool say(const std::string& text)
{
  // Any Mach call proves the kernel headers and libSystem resolved.
  if (mach_task_self() == MACH_PORT_NULL) {
    return false;
  }
  // Checking for a release past the deployment target calls into
  // compiler-rt, which the SDK does not ship.
  qos_class_t qos = QOS_CLASS_DEFAULT;
  if (__builtin_available(macOS 15.0, *)) {
    qos = QOS_CLASS_USER_INITIATED;
  }
  dispatch_queue_t queue = dispatch_get_global_queue(qos, 0);
  dispatch_semaphore_t done = dispatch_semaphore_create(0);
  dispatch_data_t data = dispatch_data_create(text.data(), text.size(), queue, DISPATCH_DATA_DESTRUCTOR_DEFAULT);
  __block bool failed = true;
  dispatch_write(STDOUT_FILENO, data, queue, ^(dispatch_data_t rest, int error) {
    failed = rest != nullptr || error != 0;
    dispatch_semaphore_signal(done);
  });
  dispatch_semaphore_wait(done, DISPATCH_TIME_FOREVER);
  return !failed;
}
#elif defined(__linux__)
static_assert(LINUX_VERSION_CODE >= KERNEL_VERSION(5, 10, 0), "the UAPI headers predate Linux 5.10");

bool say(const std::string& text)
{
  return syscall(SYS_write, STDOUT_FILENO, text.data(), text.size()) == static_cast<long>(text.size());
}
#endif

} // namespace

int main()
{
  const std::string greeting = std::string("Hello") + ", world!\n";
  return say(greeting) ? 0 : 1;
}
