/// How many keys we have inside the event data map
#define EVENT_MAP_SIZE 50

/// How many keys we have inside the string data map
#define STRING_MAP_SIZE 50

/// Event buffer size; this must be big enough to hold the biggest event data
/// structure
#define EVENT_BUFFER_SIZE sizeof(ExecveEnterEventData)

/// String buffer size
#define STRING_BUFFER_SIZE 100

// clang-format off
#define INCREMENT_MAP_INDEX_BY(idx, amount, map_size) \
  idx = ((idx + amount) & 0x00FFFFFFUL) % map_size
// clang-format on

// clang-format off
#define INCREMENT_MAP_INDEX(idx, map_size) \
  INCREMENT_MAP_INDEX_BY(idx, 1, map_size)
// clang-format on

//
// Event IDs
//

#define EVENTID_OPEN 1
#define EVENTID_CREAT 2
#define EVENTID_OPENAT 2
#define EVENTID_EXECVE 3
#define EVENTID_EXECVEAT 4

//
// Event data structures
//

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

  int dirfd;
  StringIndex pathname;
  int flags;
  int mode;
} OpenEnterEventData;

typedef struct {
  EventHeader header;
  int exit_code;
} OpenExitEventData;

typedef struct {
  EventHeader header;

  StringIndex filename;

  int argc;
  StringIndex argv[20];
} ExecveEnterEventData;

typedef struct {
  EventHeader header;
  int exit_code;
} ExecveExitEventData;
