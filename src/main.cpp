#include <bcc/BPF.h>
#include <iostream>

#include <probes/common.h>
#include <probes/execve.h>
#include <probes/types.h>

void eventCallback(void *, void *data, int byte_count) {
  static_cast<void>(data);
  std::cout << "Received " << byte_count << " bytes!\n";
}

int main() {
  ebpf::BPF bpf;
  auto s = bpf.init(probes::execve);
  if (s.code() != 0) {
    std::cerr << "Initialization error: " << s.msg() << "\n";
    return 1;
  }

  // clang-format off
  auto status = bpf.open_perf_buffer(
    "events",
    eventCallback,

    [](void *, std::uint64_t count) -> void {
      std::cerr << "Lost " << std::to_string(count) << " events!\n";
    },

    nullptr
  );
  // clang-format on

  if (status.code() != 0) {
    std::cerr << "Failed to open the perf events buffer: " << status.msg()
              << "\n";
    return 1;
  }

  status =
      bpf.attach_tracepoint("syscalls:sys_enter_execve", "on_execve_enter");
  if (status.code() != 0) {
    std::cerr << "Failed to attach the tracepoint: " << status.msg() << "\n";
    return 1;
  }

  status = bpf.poll_perf_buffer("events");
  if (status.code() != 0) {
    std::cerr << "poll failed on the perf events buffer: " << status.msg()
              << "\n";
    return 1;
  }

  return 0;
}
