#include <bcc/BPF.h>

#include <atomic>
#include <iostream>

#include <signal.h>

// clang-format off
#include <probes/types.h>
#include <probes/common.h>
#include <probes/execve.h>
// clang-format on

std::atomic_bool terminate{false};

void sigIntHandler(int s) {
  if (s == SIGINT) {
    terminate = true;
  }
}

void eventCallback(void *, void *data, int byte_count) {
  static_cast<void>(data);
  std::cout << "Received " << byte_count << " bytes!\n";
}

int main() {
  std::cout << "Initializing the BPF program...\n";

  ebpf::BPF bpf;
  auto s = bpf.init(probes::execve);
  if (s.code() != 0) {
    std::cerr << "Initialization error: " << s.msg() << "\n";
    return 1;
  }

  std::cout << "Opening the perf events buffer...\n";

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

  std::cout << "Attaching tracepoints...\n";

  status =
      bpf.attach_tracepoint("syscalls:sys_enter_execve", "on_execve_enter");

  if (status.code() != 0) {
    std::cerr << "Failed to attach the tracepoint: " << status.msg() << "\n";
    return 1;
  }

  std::cout << "Installing the SIGINT handler...\n";
  signal(SIGINT, sigIntHandler);

  std::cout << "Entering poll loop..\n";
  while (!terminate) {
    status = bpf.poll_perf_buffer("events");
  }

  return 0;
}
