#include <bcc/BPF.h>

#include <atomic>
#include <iostream>
#include <sstream>

#include <signal.h>

#include <probes/common.h>
#include <probes/execve.h>

namespace {
std::atomic_bool terminate{false};

std::optional<ebpf::BPFPercpuArrayTable<EventDataObject>> event_data_map;
std::optional<ebpf::BPFPercpuArrayTable<StringData>> string_data_map;

void sigIntHandler(int s) {
  if (s == SIGINT) {
    std::cout << "SIGINT received, interrupting the main loop...\n";
    terminate = true;
  }
}

bool getString(std::string &buffer, StringIndex string_index) {
  int raw_string_index = static_cast<int>(string_index & 0x00FFFFFF);

  auto cpu_id = static_cast<std::size_t>((string_index >> 28) & 0x000000FF);

  std::vector<StringData> string_data_vector = {};
  auto status =
      string_data_map->get_value(raw_string_index, string_data_vector);
  if (status.code() != 0) {
    return false;
  }

  const auto &string_data = string_data_vector[cpu_id];

  buffer.resize(STRING_BUFFER_SIZE);
  std::memcpy(&buffer[0], string_data.buffer, STRING_BUFFER_SIZE);

  auto null_term_index = buffer.find('\0');
  buffer.resize(null_term_index);

  return true;
}

bool processSysEnterExecveEvent(const EventDataObject &event_data) {
  const auto &execve_data = event_data.sys_enter_execve;

  std::cout << " > id:" << execve_data.header.id
            << " timestamp:" << (execve_data.header.timestamp / 1000000000ULL)
            << " ppid:" << (execve_data.header.parent_tgid)
            << " pid:" << (execve_data.header.pid_tgid >> 32)
            << " tid:" << (execve_data.header.pid_tgid & 0xFFFFFFFFULL)
            << " uid:" << (execve_data.header.uid_gid >> 32)
            << " gid:" << (execve_data.header.uid_gid & 0xFFFFFFFFULL)
            << "\n   ---\n";

  std::string filename;
  if (!getString(filename, execve_data.filename)) {
    return false;
  }

  std::stringstream argv;
  for (auto i = 0; i < execve_data.argc; i++) {
    auto arg_string_index = execve_data.argv[i];

    std::string arg_string = {};
    if (!getString(arg_string, arg_string_index)) {
      return false;
    }

    if (!argv.str().empty()) {
      argv << ", ";
    }

    argv << "\"" << arg_string << "\"";
  }

  std::cout << "   execve(\"" << filename << "\", { " << argv.str()
            << " });\n\n";
  return true;
}

void processEvents(const std::uint32_t *event_list, std::size_t event_count) {
  // clang-format off
  const std::map<std::uint64_t, bool (*)(const EventDataObject &)> event_dispatcher = {
    { CREATE_TRACEPOINT_EVENT_ID(EVENTID_SYSENTEREXECVE, 1), processSysEnterExecveEvent }
  };
  // clang-format on

  for (auto i = 0U; i < event_count; i++) {
    const auto &event_identifier = event_list[i];

    int event_data_index = static_cast<int>(event_identifier & 0x00FFFFFF);

    auto cpu_id =
        static_cast<std::size_t>((event_identifier >> 28) & 0x000000FF);

    std::vector<EventDataObject> event_data_vector = {};
    auto status =
        event_data_map->get_value(event_data_index, event_data_vector);
    if (status.code() != 0) {
      std::cerr << "Failed to read the data from the event data map\n";
      continue;
    }

    const auto &event_data = event_data_vector[cpu_id];
    auto event_type = event_data.sys_enter_execve.header.id;

    auto event_handler_it = event_dispatcher.find(event_type);
    if (event_handler_it == event_dispatcher.end()) {
      std::cerr << "Invalid event type received: " << event_type << "\n";
      continue;
    }

    const auto &event_handler = event_handler_it->second;
    if (!event_handler(event_data)) {
      std::cerr << "Failed to handle event of type " << event_type << "\n";
      continue;
    }
  }
}

void eventCallback(void *, void *data, int byte_count) {
  if ((byte_count % 4) != 0) {
    std::cout << "ERROR: Partial event identifier received\n";
    return;
  }

  processEvents(static_cast<const std::uint32_t *>(data),
                static_cast<std::size_t>(byte_count / 4));
}
} // namespace

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

  std::cout << "Opening the event and string maps...\n";

  {
    auto map = bpf.get_percpu_array_table<EventDataObject>("event_data");
    event_data_map.emplace(std::move(map));
  }

  {
    auto map = bpf.get_percpu_array_table<StringData>("string_data");
    string_data_map.emplace(std::move(map));
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
