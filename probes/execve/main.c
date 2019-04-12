#include <linux/sched.h>

/// How many keys we have inside the event data map
#define EVENT_MAP_SIZE 1000

/// How many keys we have inside the string data map
#define STRING_MAP_SIZE 1000

// clang-format off
#define INCREMENT_MAP_INDEX_BY(idx, amount, map_size) \
  idx = ((idx + amount) & 0x00FFFFFFUL) % map_size
// clang-format on

// clang-format off
#define INCREMENT_MAP_INDEX(idx, map_size) \
  INCREMENT_MAP_INDEX_BY(idx, 1, map_size)
// clang-format on

//
// BPF maps
//

BPF_PERF_OUTPUT(events);

BPF_PERCPU_ARRAY(event_data, EventData, EVENT_MAP_SIZE);
BPF_PERCPU_ARRAY(event_data_index, int, 1);

BPF_PERCPU_ARRAY(string_data, StringData, STRING_MAP_SIZE);
BPF_PERCPU_ARRAY(string_data_index, int, 1);

/// Returns the string data map index
static int getStringMapIndex() {
  int key = 0;
  int *index_ptr = string_data_index.lookup_or_init(&key, &key);
  if (index_ptr == NULL) {
    return 0;
  }

  return *index_ptr;
}

/// Returns the event data map index
static int getEventMapIndex() {
  int key = 0;
  int *index_ptr = event_data_index.lookup_or_init(&key, &key);
  if (index_ptr == NULL) {
    return 0;
  }

  return *index_ptr;
}

/// Updates the string data map index
static void setStringMapIndex(int index) {
  int key = 0;
  string_data_index.update(&key, &index);
}

/// Updates the event data map index
static void setEventMapIndex(int index) {
  int key = 0;
  event_data_index.update(&key, &index);
}

/// Saves the given string to the string data map
static int saveString(const char *string_ptr, int *external_index) {
  int index = getStringMapIndex();

  StringData *string_data_slot = string_data.lookup(&index);
  if (string_data_slot == NULL) {
    return 1;
  }

  *external_index =
      (((struct task_struct *)bpf_get_current_task())->cpu << 28) |
      (index & 0x00FFFFFF);

  INCREMENT_MAP_INDEX(index, STRING_MAP_SIZE);
  setStringMapIndex(index);

  bpf_probe_read(string_data_slot->buffer, sizeof(string_data_slot->buffer),
                 string_ptr);
  return 0;
}

/// Dereferences the given pointer and saves the string to the string data map
static int saveStringFromAddress(const void *string_ptr, int *external_index) {
  const char *ptr = NULL;
  bpf_probe_read(&ptr, sizeof(ptr), string_ptr);
  if (ptr == NULL) {
    return 1;
  }

  return saveString(ptr, external_index);
}

/// Populates the event header
static void fillEventHeader(EventHeader *event_header, u64 event_id) {
  event_header->id = event_id;
  event_header->timestamp = bpf_ktime_get_ns();
  event_header->pid_tgid = bpf_get_current_pid_tgid();
  event_header->uid_gid = bpf_get_current_uid_gid();

  const struct task_struct *current_task =
      (const struct task_struct *)bpf_get_current_task();

  event_header->parent_tgid = current_task->real_parent->tgid;
}

/// Generates an external index (i.e. index + cpu id)
static int generateExternalIndex(int index) {
  return (((struct task_struct *)bpf_get_current_task())->cpu << 28) |
         (index & 0x00FFFFFF);
}

int on_execve_enter(struct tracepoint__syscalls__sys_enter_execve *args) {
  int index = getEventMapIndex();
  int event_index = generateExternalIndex(index);

  EventData *event_data_slot = event_data.lookup(&index);
  if (event_data_slot == NULL) {
    return 1;
  }

  INCREMENT_MAP_INDEX(index, EVENT_MAP_SIZE);
  setEventMapIndex(index);

  ExecveEnterEventData *event = (ExecveEnterEventData *)event_data_slot->buffer;

  fillEventHeader(&event->header,
                  CREATE_TRACEPOINT_EVENT_ID(EVENTID_SYSENTEREXECVE, 1));
  saveString(args->filename, &event->filename);

  int external_string_index = 0;

#pragma unroll
  for (int i = 0; i < (sizeof(event->argv) / sizeof(StringIndex)); ++i) {
    event->argc = i;

    if (saveStringFromAddress(&args->argv[i], &external_string_index) != 0) {
      break;
    }

    event->argv[i] = external_string_index;
  }

  events.perf_submit(args, &event_index, sizeof(event_index));
  return 0;
}
