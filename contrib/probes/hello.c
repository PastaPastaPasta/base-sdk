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

static const char greeting[] = "Hello, world!\n";

#if defined(_WIN32)
static int say(const char* text, DWORD length)
{
  HANDLE out = GetStdHandle(STD_OUTPUT_HANDLE);
  DWORD written = 0;
  return out != INVALID_HANDLE_VALUE && WriteFile(out, text, length, &written, NULL) && written == length;
}
#elif defined(__APPLE__)
static int say(const char* text, size_t length)
{
  // Any Mach call proves the kernel headers and libSystem resolved.
  if (mach_task_self() == MACH_PORT_NULL) {
    return 0;
  }
  // Checking for a release past the deployment target calls into
  // compiler-rt, which the SDK does not ship.
  qos_class_t qos = QOS_CLASS_DEFAULT;
  if (__builtin_available(macOS 15.0, *)) {
    qos = QOS_CLASS_USER_INITIATED;
  }
  dispatch_queue_t queue = dispatch_get_global_queue(qos, 0);
  dispatch_semaphore_t done = dispatch_semaphore_create(0);
  dispatch_data_t data = dispatch_data_create(text, length, queue, DISPATCH_DATA_DESTRUCTOR_DEFAULT);
  __block int failed = 1;
  dispatch_write(STDOUT_FILENO, data, queue, ^(dispatch_data_t rest, int error) {
    failed = rest != NULL || error != 0;
    dispatch_semaphore_signal(done);
  });
  dispatch_semaphore_wait(done, DISPATCH_TIME_FOREVER);
  return !failed;
}
#elif defined(__linux__)
_Static_assert(LINUX_VERSION_CODE >= KERNEL_VERSION(5, 10, 0), "the UAPI headers predate Linux 5.10");

static int say(const char* text, size_t length)
{
  return syscall(SYS_write, STDOUT_FILENO, text, length) == (long)length;
}
#endif

int main(void)
{
  return say(greeting, sizeof(greeting) - 1) ? 0 : 1;
}
