#ifdef __cplusplus
#include <cstdint>

using u8 = std::uint8_t;
using u64 = std::uint64_t;
#endif

/// Event buffer size; this must be big enough to hold the biggest event data
/// structure
#define EVENT_BUFFER_SIZE sizeof(ExecveEnterEventData)

/// String buffer size
#define STRING_BUFFER_SIZE 2048

//
// Event IDs and related utilities
//

// clang-format off
#define CREATE_EVENT_ID(id, is_tracepoint, is_enter_event) \
  (((u64) id) | ((u64) (is_tracepoint != 0 ? 0x8000000000000000ULL : 0)) | ((u64) (is_enter_event != 0 ? 0x4000000000000000ULL : 0)))
// clang-format on

// clang-format off
#define CREATE_TRACEPOINT_EVENT_ID(id, is_enter_event) \
  CREATE_EVENT_ID(id, 1, is_enter_event)
// clang-format on

// clang-format off
#define CREATE_KPROBE_EVENT_ID(id, is_enter_event) \
  CREATE_EVENT_ID(id, 0, is_enter_event)
// clang-format on

#define EVENTID_SYSENTEREXECVE 1

//
// Event data structures
//

#ifdef __cplusplus
#pragma pack(push, 1)
#endif

typedef int StringIndex;

typedef struct {
  u64 id;
  u64 timestamp;
  u64 pid_tgid;
  u64 parent_tgid;
  u64 uid_gid;
} EventHeader;

typedef struct {
  EventHeader header;

  StringIndex filename;

  int argc;
  StringIndex argv[20];
} ExecveEnterEventData;

// Base data structures
typedef struct {
  u8 buffer[EVENT_BUFFER_SIZE];
} EventData;

typedef struct {
  u8 buffer[STRING_BUFFER_SIZE];
} StringData;

#ifdef __cplusplus
union EventDataObject final {
  ExecveEnterEventData sys_enter_execve;
};

static_assert(sizeof(EventDataObject) == EVENT_BUFFER_SIZE,
              "The event buffer size must be equal to EVENT_BUFFER_SIZE");

static_assert(EVENT_BUFFER_SIZE % 8 == 0,
              "The event buffer size must be aligned to 8 bytes");

#pragma pack(pop)
#endif
