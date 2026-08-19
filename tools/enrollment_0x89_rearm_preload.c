/*
 * Repository-local, experimental enrollment interposer.
 *
 * The only interposed driver function is cv_fingerprint_update_enrollment().
 * The default legacy-repeat policy makes exactly one additional call after
 * 0x59, preserving the original diagnostic behavior.  The explicitly
 * selected fresh-stop-before-commit policies never repeat 0x59 and block a
 * native nonzero completion before the outer state machine can enter generic
 * commit.  The fresh-rearm variant additionally sends one target-local 0x8a
 * after each accepted incomplete update, with a four-update hard stop.
 * The zero-input fresh-rearm variant has the same boundaries and changes only
 * the required 20-byte UpdateEnrollment input to a stable all-zero buffer.
 *
 * A 0x89 result causes the existing target-local
 * cv_cmd_enrollment_started()/0x8a function to run before the original 0x89
 * is returned to the unchanged TOD retry callback.
 *
 * The proprietary TOD plugin is loaded with G_MODULE_BIND_LOCAL.  Therefore
 * RTLD_NEXT is intentionally never used.  Original symbols are resolved from
 * a verified RTLD_NOLOAD handle for the exact already-loaded target DSO.
 */

#define _GNU_SOURCE

#include <dlfcn.h>
#include <errno.h>
#include <limits.h>
#include <link.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#define CV_STATUS_SUCCESS 0x00u
#define CV_STATUS_UPDATE_AGAIN_EXPERIMENT 0x59u
#define CV_STATUS_BAD_CAPTURE 0x89u
#define CV_STATUS_CAPTURE_FAILED 0xa4u
#define CV_STATUS_ENROLL_MORE 0x8fu
#define CV_STATUS_EXPERIMENT_FAILURE 0x100003u
#define CV2_TARGET_ENV "CV2_0X89_TARGET_PATH"
#define CV2_UPDATE_POLICY_ENV "CV2_ENROLLMENT_UPDATE_POLICY"
#define CV2_METADATA_TRACE_ENV "CV2_UPDATE_METADATA_TRACE"
#define CV2_POLICY_LEGACY "legacy-repeat"
#define CV2_POLICY_FRESH "fresh-stop-before-commit"
#define CV2_POLICY_FRESH_REARM "fresh-rearm-stop-before-commit"
#define CV2_POLICY_ZERO_INPUT_FRESH_REARM \
  "zero-input-fresh-rearm-stop-before-commit"
#define CV2_MAX_ACCEPTED_UPDATES 4u
#define CV2_MAX_ZERO_INPUT_UPDATES 24u
#define CV2_ENROLLMENT_VALUE_SIZE 20u

typedef enum
{
  UPDATE_POLICY_LEGACY_REPEAT,
  UPDATE_POLICY_FRESH_STOP_BEFORE_COMMIT,
  UPDATE_POLICY_FRESH_REARM_STOP_BEFORE_COMMIT,
  UPDATE_POLICY_ZERO_INPUT_FRESH_REARM_STOP_BEFORE_COMMIT,
} UpdatePolicy;

typedef uint32_t (*cv_cmd_enrollment_started_fn) (void);
typedef uint32_t (*cv_fingerprint_update_enrollment_fn) (
  uint32_t handle,
  const void *enrollment_id,
  uint32_t auxiliary_input_size,
  const void *auxiliary_input,
  uint8_t *completion_out,
  void *enrollment_data_out,
  uint32_t *output_value_out);

typedef struct
{
  char path[PATH_MAX];
  dev_t device;
  ino_t inode;
} TargetIdentity;

typedef struct
{
  TargetIdentity expected;
  bool found;
} LoadedSearch;

typedef struct
{
  void *handle;
  cv_fingerprint_update_enrollment_fn update;
  cv_cmd_enrollment_started_fn enrollment_started;
  UpdatePolicy update_policy;
  bool metadata_trace;
  bool ready;
  char failure[512];
} ResolverCache;

uint32_t cv_fingerprint_update_enrollment (uint32_t handle,
                                           const void *enrollment_id,
                                           uint32_t auxiliary_input_size,
                                           const void *auxiliary_input,
                                           uint8_t *completion_out,
                                           void *enrollment_data_out,
                                           uint32_t *output_value_out);

static pthread_once_t resolver_once = PTHREAD_ONCE_INIT;
static ResolverCache resolver;
static atomic_uint retry_attempt = 0;
static atomic_uint accepted_incomplete_count = 0;
static atomic_uint update_call_count = 0;
static atomic_uint zero_input_update_count = 0;
/* Writable in case the proprietary ABI treats this nominal input as in/out. */
static unsigned char zero_update_input[CV2_ENROLLMENT_VALUE_SIZE] = { 0 };

typedef struct
{
  bool initialized;
  uint32_t first_handle;
  const void *previous_enrollment_id_pointer;
  unsigned char previous_enrollment_id[CV2_ENROLLMENT_VALUE_SIZE];
  bool previous_enrollment_id_valid;
  const void *previous_auxiliary_input;
  uint8_t *first_completion_out;
  void *first_enrollment_data_out;
  uint32_t *first_output_value_out;
  unsigned char previous_enrollment_output[CV2_ENROLLMENT_VALUE_SIZE];
  bool previous_enrollment_output_valid;
} MetadataTraceState;

static pthread_mutex_t metadata_trace_lock = PTHREAD_MUTEX_INITIALIZER;
static MetadataTraceState metadata_trace_state;

static const char *
update_policy_name (UpdatePolicy policy)
{
  switch (policy)
    {
    case UPDATE_POLICY_LEGACY_REPEAT:
      return CV2_POLICY_LEGACY;
    case UPDATE_POLICY_FRESH_STOP_BEFORE_COMMIT:
      return CV2_POLICY_FRESH;
    case UPDATE_POLICY_FRESH_REARM_STOP_BEFORE_COMMIT:
      return CV2_POLICY_FRESH_REARM;
    case UPDATE_POLICY_ZERO_INPUT_FRESH_REARM_STOP_BEFORE_COMMIT:
      return CV2_POLICY_ZERO_INPUT_FRESH_REARM;
    }
  return "<invalid>";
}

static bool
update_policy_rearms_accepted (UpdatePolicy policy)
{
  return policy == UPDATE_POLICY_FRESH_REARM_STOP_BEFORE_COMMIT ||
         policy == UPDATE_POLICY_ZERO_INPUT_FRESH_REARM_STOP_BEFORE_COMMIT;
}

static void
resolver_failure (const char *format, ...)
{
  va_list args;

  va_start (args, format);
  vsnprintf (resolver.failure, sizeof resolver.failure, format, args);
  va_end (args);
  fprintf (stderr,
           "[cv2-0x89-resolver] symbol resolution failed: %s\n",
           resolver.failure);
}

static bool
identity_from_path (const char *path, TargetIdentity *identity)
{
  struct stat metadata;

  if (path == NULL || path[0] == '\0')
    return false;
  if (realpath (path, identity->path) == NULL)
    return false;
  if (stat (identity->path, &metadata) != 0)
    return false;
  identity->device = metadata.st_dev;
  identity->inode = metadata.st_ino;
  return true;
}

static int
find_loaded_target (struct dl_phdr_info *info, size_t size, void *user_data)
{
  LoadedSearch *search = user_data;
  TargetIdentity candidate;

  (void) size;
  if (!identity_from_path (info->dlpi_name, &candidate))
    return 0;
  if (strcmp (candidate.path, search->expected.path) == 0 &&
      candidate.device == search->expected.device &&
      candidate.inode == search->expected.inode)
    {
      search->found = true;
      return 1;
    }
  return 0;
}

static bool
symbol_owned_by_target (void *address,
                        const char *name,
                        const TargetIdentity *target,
                        void *self_address)
{
  Dl_info owner;
  TargetIdentity owner_identity;

  if (address == NULL)
    {
      resolver_failure ("target symbol %s was not found", name);
      return false;
    }
  if (address == self_address)
    {
      resolver_failure (
        "target symbol %s resolved to the interposer wrapper; refusing recursion",
        name);
      return false;
    }
  memset (&owner, 0, sizeof owner);
  if (dladdr (address, &owner) == 0 || owner.dli_fname == NULL)
    {
      resolver_failure ("dladdr could not identify owner of %s", name);
      return false;
    }
  if (!identity_from_path (owner.dli_fname, &owner_identity))
    {
      resolver_failure ("could not canonicalize owner of %s: %s",
                        name,
                        owner.dli_fname);
      return false;
    }
  if (strcmp (owner_identity.path, target->path) != 0 ||
      owner_identity.device != target->device ||
      owner_identity.inode != target->inode)
    {
      resolver_failure ("symbol %s belongs to unexpected DSO %s",
                        name,
                        owner_identity.path);
      return false;
    }
  fprintf (stderr,
           "[cv2-0x89-resolver] original symbol resolved from target handle: "
           "%s\n",
           name);
  fprintf (stderr,
           "[cv2-0x89-resolver] dladdr target verification passed: %s\n",
           name);
  return true;
}

static void
initialize_resolver (void)
{
  const char *configured_path = getenv (CV2_TARGET_ENV);
  const char *configured_policy = getenv (CV2_UPDATE_POLICY_ENV);
  const char *configured_metadata_trace = getenv (CV2_METADATA_TRACE_ENV);
  LoadedSearch search = { 0 };
  void *update_address;
  void *enrollment_started_address;
  const char *dynamic_error;

  if (!identity_from_path (configured_path, &search.expected))
    {
      resolver_failure ("invalid or missing %s: %s",
                        CV2_TARGET_ENV,
                        configured_path != NULL ? configured_path : "<unset>");
      return;
    }

  if (configured_policy == NULL ||
      strcmp (configured_policy, CV2_POLICY_LEGACY) == 0)
    resolver.update_policy = UPDATE_POLICY_LEGACY_REPEAT;
  else if (strcmp (configured_policy, CV2_POLICY_FRESH) == 0)
    resolver.update_policy = UPDATE_POLICY_FRESH_STOP_BEFORE_COMMIT;
  else if (strcmp (configured_policy, CV2_POLICY_FRESH_REARM) == 0)
    resolver.update_policy = UPDATE_POLICY_FRESH_REARM_STOP_BEFORE_COMMIT;
  else if (strcmp (configured_policy, CV2_POLICY_ZERO_INPUT_FRESH_REARM) == 0)
    resolver.update_policy =
      UPDATE_POLICY_ZERO_INPUT_FRESH_REARM_STOP_BEFORE_COMMIT;
  else
    {
      resolver_failure ("invalid %s: %s",
                        CV2_UPDATE_POLICY_ENV,
                        configured_policy);
      return;
    }
  if (configured_metadata_trace == NULL ||
      strcmp (configured_metadata_trace, "0") == 0)
    resolver.metadata_trace = false;
  else if (strcmp (configured_metadata_trace, "1") == 0)
    resolver.metadata_trace = true;
  else
    {
      resolver_failure ("invalid %s: %s",
                        CV2_METADATA_TRACE_ENV,
                        configured_metadata_trace);
      return;
    }
  fprintf (stderr,
           "[cv2-enrollment-policy] selected=%s\n",
           update_policy_name (resolver.update_policy));
  fprintf (stderr,
           "[cv2-update-metadata] selected=%s\n",
           resolver.metadata_trace ? "enabled" : "disabled");
  fprintf (stderr,
           "[cv2-0x89-resolver] expected target path: %s\n",
           search.expected.path);

  dl_iterate_phdr (find_loaded_target, &search);
  if (!search.found)
    {
      resolver_failure (
        "expected target is not present in the loaded DSO list; refusing "
        "RTLD_NOLOAD lookup");
      return;
    }
  fprintf (stderr,
           "[cv2-0x89-resolver] loaded target discovered: %s\n",
           search.expected.path);

  dlerror ();
  resolver.handle = dlopen (search.expected.path, RTLD_LAZY | RTLD_NOLOAD);
  dynamic_error = dlerror ();
  if (resolver.handle == NULL || dynamic_error != NULL)
    {
      resolver.handle = NULL;
      resolver_failure ("RTLD_NOLOAD handle acquisition failed: %s",
                        dynamic_error != NULL ? dynamic_error : "unknown error");
      return;
    }
  fprintf (stderr,
           "[cv2-0x89-resolver] RTLD_NOLOAD handle acquired\n");

  dlerror ();
  update_address = dlsym (resolver.handle,
                          "cv_fingerprint_update_enrollment");
  dynamic_error = dlerror ();
  if (dynamic_error != NULL)
    update_address = NULL;
  if (!symbol_owned_by_target (
        update_address,
        "cv_fingerprint_update_enrollment",
        &search.expected,
        (void *) cv_fingerprint_update_enrollment))
    return;

  dlerror ();
  enrollment_started_address = dlsym (resolver.handle,
                                      "cv_cmd_enrollment_started");
  dynamic_error = dlerror ();
  if (dynamic_error != NULL)
    enrollment_started_address = NULL;
  if (!symbol_owned_by_target (enrollment_started_address,
                               "cv_cmd_enrollment_started",
                               &search.expected,
                               NULL))
    return;

  resolver.update =
    (cv_fingerprint_update_enrollment_fn) update_address;
  resolver.enrollment_started =
    (cv_cmd_enrollment_started_fn) enrollment_started_address;
  resolver.ready = true;
  fprintf (stderr,
           "[cv2-0x89-resolver] local-scope forwarding ready\n");
}

static bool
forwarding_ready (void)
{
  int once_status = pthread_once (&resolver_once, initialize_resolver);

  if (once_status != 0)
    {
      resolver_failure ("pthread_once failed: %s", strerror (once_status));
      return false;
    }
  return resolver.ready;
}

/*
 * Called by the repository-local hardware harness after FpContext has loaded
 * the TOD plugin, but before opening the device or starting enrollment.
 */
int
cv2_0x89_forwarding_ready (void)
{
  if (!forwarding_ready ())
    {
      fprintf (stderr,
               "[cv2-0x89-resolver] refusing operation before hardware "
               "command: %s\n",
               resolver.failure[0] != '\0'
                 ? resolver.failure
                 : "resolver is not ready");
      return 0;
    }
  return 1;
}

static uint32_t
fatalize_rearm_status (uint32_t status)
{
  if (status == CV_STATUS_BAD_CAPTURE ||
      status == CV_STATUS_CAPTURE_FAILED ||
      status == CV_STATUS_ENROLL_MORE)
    return CV_STATUS_EXPERIMENT_FAILURE;
  return status;
}

static void
log_update_outputs (const char *which,
                    const uint8_t *completion_out,
                    const void *enrollment_data_out,
                    const uint32_t *output_value_out)
{
  fprintf (stderr, "[cv2-0x59-experiment] %s completion=", which);
  if (completion_out == NULL)
    fprintf (stderr, "<null>");
  else
    fprintf (stderr, "0x%02x", (unsigned int) *completion_out);

  fprintf (stderr,
           " enrollment_output=%s output_value=%s\n",
           enrollment_data_out == NULL ? "<null>" : "<redacted>",
           output_value_out == NULL ? "<null>" : "<redacted>");
}

static bool
buffer_is_zero (const void *buffer, size_t size)
{
  const unsigned char *bytes = buffer;

  for (size_t index = 0; index < size; index++)
    if (bytes[index] != 0)
      return false;
  return true;
}

static const char *
pointer_relation (const void *current, const void *reference, bool first_call)
{
  if (first_call)
    return "first";
  return current == reference ? "same" : "changed";
}

static const char *
value_relation_u32 (uint32_t current, uint32_t reference, bool first_call)
{
  if (first_call)
    return "first";
  return current == reference ? "same" : "changed";
}

typedef struct
{
  unsigned int call;
  bool completion_valid;
  uint8_t completion;
  bool enrollment_output_valid;
  unsigned char enrollment_output[CV2_ENROLLMENT_VALUE_SIZE];
  bool output_value_valid;
  unsigned char output_value[sizeof (uint32_t)];
} MetadataBeforeCall;

static MetadataBeforeCall
metadata_before_update (uint32_t handle,
                        const void *enrollment_id,
                        uint32_t auxiliary_input_size,
                        const void *auxiliary_input,
                        uint8_t *completion_out,
                        void *enrollment_data_out,
                        uint32_t *output_value_out)
{
  MetadataBeforeCall before = { 0 };
  bool first_call;
  const char *id_content_relation;
  const char *id_matches_previous_output;
  const char *aux_matches_previous_output;

  before.call = atomic_fetch_add_explicit (&update_call_count,
                                           1,
                                           memory_order_relaxed)
                + 1;
  before.completion_valid = completion_out != NULL;
  if (before.completion_valid)
    before.completion = *completion_out;
  before.enrollment_output_valid = enrollment_data_out != NULL;
  if (before.enrollment_output_valid)
    memcpy (before.enrollment_output,
            enrollment_data_out,
            CV2_ENROLLMENT_VALUE_SIZE);
  before.output_value_valid = output_value_out != NULL;
  if (before.output_value_valid)
    memcpy (before.output_value,
            output_value_out,
            sizeof before.output_value);

  pthread_mutex_lock (&metadata_trace_lock);
  first_call = !metadata_trace_state.initialized;
  if (first_call || enrollment_id == NULL ||
      !metadata_trace_state.previous_enrollment_id_valid)
    id_content_relation = first_call ? "first" : "unavailable";
  else
    id_content_relation =
      memcmp (enrollment_id,
              metadata_trace_state.previous_enrollment_id,
              CV2_ENROLLMENT_VALUE_SIZE) == 0
        ? "same"
        : "changed";

  if (first_call || enrollment_id == NULL ||
      !metadata_trace_state.previous_enrollment_output_valid)
    id_matches_previous_output = "unavailable";
  else
    id_matches_previous_output =
      memcmp (enrollment_id,
              metadata_trace_state.previous_enrollment_output,
              CV2_ENROLLMENT_VALUE_SIZE) == 0
        ? "yes"
        : "no";

  if (first_call || auxiliary_input == NULL ||
      auxiliary_input_size != CV2_ENROLLMENT_VALUE_SIZE ||
      !metadata_trace_state.previous_enrollment_output_valid)
    aux_matches_previous_output = "unavailable";
  else
    aux_matches_previous_output =
      memcmp (auxiliary_input,
              metadata_trace_state.previous_enrollment_output,
              CV2_ENROLLMENT_VALUE_SIZE) == 0
        ? "yes"
        : "no";

  fprintf (stderr,
           "[cv2-update-metadata] call=%u phase=before "
           "handle_relation=%s enrollment_id_presence=%s "
           "enrollment_id_pointer_relation=%s "
           "enrollment_id_content_relation=%s "
           "enrollment_id_matches_previous_output=%s "
           "auxiliary_size=%u auxiliary_presence=%s "
           "auxiliary_pointer_relation=%s "
           "auxiliary_matches_previous_output=%s\n",
           before.call,
           value_relation_u32 (handle,
                               metadata_trace_state.first_handle,
                               first_call),
           enrollment_id != NULL ? "present" : "null",
           pointer_relation (enrollment_id,
                             metadata_trace_state.previous_enrollment_id_pointer,
                             first_call),
           id_content_relation,
           id_matches_previous_output,
           auxiliary_input_size,
           auxiliary_input != NULL ? "present" : "null",
           pointer_relation (auxiliary_input,
                             metadata_trace_state.previous_auxiliary_input,
                             first_call),
           aux_matches_previous_output);
  fprintf (stderr,
           "[cv2-update-metadata] call=%u phase=before-buffers "
           "completion_pointer_relation=%s completion_pre_zero=%s "
           "enrollment_output_pointer_relation=%s "
           "enrollment_output_pre_zero=%s "
           "output_value_pointer_relation=%s output_value_pre_zero=%s\n",
           before.call,
           pointer_relation (completion_out,
                             metadata_trace_state.first_completion_out,
                             first_call),
           !before.completion_valid
             ? "unavailable"
             : before.completion == 0 ? "yes" : "no",
           pointer_relation (enrollment_data_out,
                             metadata_trace_state.first_enrollment_data_out,
                             first_call),
           !before.enrollment_output_valid
             ? "unavailable"
             : buffer_is_zero (before.enrollment_output,
                               CV2_ENROLLMENT_VALUE_SIZE)
                 ? "yes"
                 : "no",
           pointer_relation (output_value_out,
                             metadata_trace_state.first_output_value_out,
                             first_call),
           !before.output_value_valid
             ? "unavailable"
             : buffer_is_zero (before.output_value,
                               sizeof before.output_value)
                 ? "yes"
                 : "no");

  if (first_call)
    {
      metadata_trace_state.first_handle = handle;
      metadata_trace_state.first_completion_out = completion_out;
      metadata_trace_state.first_enrollment_data_out = enrollment_data_out;
      metadata_trace_state.first_output_value_out = output_value_out;
      metadata_trace_state.initialized = true;
    }
  metadata_trace_state.previous_enrollment_id_pointer = enrollment_id;
  metadata_trace_state.previous_auxiliary_input = auxiliary_input;
  if (enrollment_id != NULL)
    {
      memcpy (metadata_trace_state.previous_enrollment_id,
              enrollment_id,
              CV2_ENROLLMENT_VALUE_SIZE);
      metadata_trace_state.previous_enrollment_id_valid = true;
    }
  else
    metadata_trace_state.previous_enrollment_id_valid = false;
  pthread_mutex_unlock (&metadata_trace_lock);
  return before;
}

static void
metadata_after_update (const MetadataBeforeCall *before,
                       uint32_t status,
                       const uint8_t *completion_out,
                       const void *enrollment_data_out,
                       const uint32_t *output_value_out)
{
  const char *completion_changed;
  const char *enrollment_output_changed;
  const char *output_value_changed;

  completion_changed =
    !before->completion_valid || completion_out == NULL
      ? "unavailable"
      : before->completion == *completion_out ? "no" : "yes";
  enrollment_output_changed =
    !before->enrollment_output_valid || enrollment_data_out == NULL
      ? "unavailable"
      : memcmp (before->enrollment_output,
                enrollment_data_out,
                CV2_ENROLLMENT_VALUE_SIZE) == 0
          ? "no"
          : "yes";
  output_value_changed =
    !before->output_value_valid || output_value_out == NULL
      ? "unavailable"
      : memcmp (before->output_value,
                output_value_out,
                sizeof before->output_value) == 0
          ? "no"
          : "yes";

  fprintf (stderr,
           "[cv2-update-metadata] call=%u phase=after native_status=0x%x "
           "completion_post_zero=%s completion_changed=%s "
           "enrollment_output_post_zero=%s "
           "enrollment_output_changed=%s output_value_post_zero=%s "
           "output_value_changed=%s\n",
           before->call,
           status,
           completion_out == NULL
             ? "unavailable"
             : *completion_out == 0 ? "yes" : "no",
           completion_changed,
           enrollment_data_out == NULL
             ? "unavailable"
             : buffer_is_zero (enrollment_data_out,
                               CV2_ENROLLMENT_VALUE_SIZE)
                 ? "yes"
                 : "no",
           enrollment_output_changed,
           output_value_out == NULL
             ? "unavailable"
             : buffer_is_zero (output_value_out, sizeof *output_value_out)
                 ? "yes"
                 : "no",
           output_value_changed);

  pthread_mutex_lock (&metadata_trace_lock);
  if (enrollment_data_out != NULL)
    {
      memcpy (metadata_trace_state.previous_enrollment_output,
              enrollment_data_out,
              CV2_ENROLLMENT_VALUE_SIZE);
      metadata_trace_state.previous_enrollment_output_valid = true;
    }
  else
    metadata_trace_state.previous_enrollment_output_valid = false;
  pthread_mutex_unlock (&metadata_trace_lock);
}

uint32_t
cv_fingerprint_update_enrollment (uint32_t handle,
                                  const void *enrollment_id,
                                  uint32_t auxiliary_input_size,
                                  const void *auxiliary_input,
                                  uint8_t *completion_out,
                                  void *enrollment_data_out,
                                  uint32_t *output_value_out)
{
  MetadataBeforeCall metadata_before = { 0 };
  const void *effective_enrollment_id = enrollment_id;
  uint32_t status;
  uint32_t rearm_status;
  unsigned int attempt;

  if (!forwarding_ready ())
    {
      fprintf (stderr,
               "[cv2-0x89-resolver] refusing operation before hardware "
               "command: %s\n",
               resolver.failure[0] != '\0'
                 ? resolver.failure
                 : "resolver is not ready");
      return CV_STATUS_EXPERIMENT_FAILURE;
    }

  if (resolver.update_policy ==
      UPDATE_POLICY_ZERO_INPUT_FRESH_REARM_STOP_BEFORE_COMMIT)
    {
      unsigned int zero_input_call;

      if (enrollment_id == NULL)
        {
          fprintf (stderr,
                   "[cv2-zero-input] required source input is null; "
                   "refusing before native UpdateEnrollment\n");
          return CV_STATUS_EXPERIMENT_FAILURE;
        }
      zero_input_call = atomic_fetch_add_explicit (&zero_input_update_count,
                                                   1,
                                                   memory_order_relaxed)
                        + 1;
      if (zero_input_call > CV2_MAX_ZERO_INPUT_UPDATES)
        {
          fprintf (stderr,
                   "[cv2-zero-input] total update limit reached; "
                   "refusing native UpdateEnrollment call=%u limit=%u\n",
                   zero_input_call,
                   CV2_MAX_ZERO_INPUT_UPDATES);
          return CV_STATUS_EXPERIMENT_FAILURE;
        }
      memset (zero_update_input, 0, sizeof zero_update_input);
      effective_enrollment_id = zero_update_input;
      fprintf (stderr,
               "[cv2-zero-input] native UpdateEnrollment call=%u/%u "
               "input=stable-zero-20 source_bytes_read=no\n",
               zero_input_call,
               CV2_MAX_ZERO_INPUT_UPDATES);
    }

  if (resolver.metadata_trace)
    metadata_before = metadata_before_update (handle,
                                              effective_enrollment_id,
                                              auxiliary_input_size,
                                              auxiliary_input,
                                              completion_out,
                                              enrollment_data_out,
                                              output_value_out);
  status = resolver.update (handle,
                            effective_enrollment_id,
                            auxiliary_input_size,
                            auxiliary_input,
                            completion_out,
                            enrollment_data_out,
                            output_value_out);
  if (resolver.metadata_trace)
    metadata_after_update (&metadata_before,
                           status,
                           completion_out,
                           enrollment_data_out,
                           output_value_out);
  if (resolver.update_policy != UPDATE_POLICY_LEGACY_REPEAT)
    {
      fprintf (stderr,
               "[cv2-fresh-boundary] native UpdateEnrollment status=0x%x\n",
               status);
      log_update_outputs ("native",
                          completion_out,
                          enrollment_data_out,
                          output_value_out);
      if (status == CV_STATUS_UPDATE_AGAIN_EXPERIMENT)
        fprintf (stderr,
                 "[cv2-fresh-boundary] preserving native 0x59 without "
                 "same-update replay\n");
      if (status == CV_STATUS_SUCCESS &&
          (completion_out == NULL || *completion_out != 0))
        {
          fprintf (stderr,
                   "[cv2-fresh-boundary] native completion boundary "
                   "observed; blocking state 2 and generic commit\n");
          return CV_STATUS_EXPERIMENT_FAILURE;
        }
      if (update_policy_rearms_accepted (resolver.update_policy) &&
          status == CV_STATUS_SUCCESS && completion_out != NULL &&
          *completion_out == 0)
        {
          unsigned int accepted = atomic_fetch_add_explicit (
                                    &accepted_incomplete_count,
                                    1,
                                    memory_order_relaxed)
                                  + 1;

          fprintf (stderr,
                   "[cv2-fresh-rearm] accepted incomplete update; "
                   "accepted=%u/%u\n",
                   accepted,
                   CV2_MAX_ACCEPTED_UPDATES);
          if (accepted >= CV2_MAX_ACCEPTED_UPDATES)
            {
              fprintf (stderr,
                       "[cv2-fresh-rearm] accepted-update limit reached "
                       "without native completion; blocking another "
                       "capture\n");
              return CV_STATUS_EXPERIMENT_FAILURE;
            }

          attempt = atomic_fetch_add_explicit (&retry_attempt,
                                               1,
                                               memory_order_relaxed)
                    + 1;
          fprintf (stderr,
                   "[cv2-fresh-rearm] re-arming accepted incomplete "
                   "enrollment with command 0x8A; attempt=%u\n",
                   attempt);
          rearm_status = resolver.enrollment_started ();
          if (rearm_status != CV_STATUS_SUCCESS)
            {
              fprintf (stderr,
                       "[cv2-fresh-rearm] 0x8A failed with status 0x%x; "
                       "attempt=%u\n",
                       rearm_status,
                       attempt);
              return fatalize_rearm_status (rearm_status);
            }
          fprintf (stderr,
                   "[cv2-fresh-rearm] 0x8A completed successfully; "
                   "attempt=%u\n",
                   attempt);
        }
    }
  else if (status == CV_STATUS_UPDATE_AGAIN_EXPERIMENT)
    {
      fprintf (stderr,
               "[cv2-0x59-experiment] 0x59 UpdateEnrollment result "
               "received\n");
      log_update_outputs ("first",
                          completion_out,
                          enrollment_data_out,
                          output_value_out);
      fprintf (stderr,
               "[cv2-0x59-experiment] retrying the same UpdateEnrollment "
               "once\n");

      if (resolver.metadata_trace)
        metadata_before = metadata_before_update (handle,
                                                  enrollment_id,
                                                  auxiliary_input_size,
                                                  auxiliary_input,
                                                  completion_out,
                                                  enrollment_data_out,
                                                  output_value_out);
      status = resolver.update (handle,
                                enrollment_id,
                                auxiliary_input_size,
                                auxiliary_input,
                                completion_out,
                                enrollment_data_out,
                                output_value_out);
      if (resolver.metadata_trace)
        metadata_after_update (&metadata_before,
                               status,
                               completion_out,
                               enrollment_data_out,
                               output_value_out);
      fprintf (stderr,
               "[cv2-0x59-experiment] second UpdateEnrollment status=0x%x\n",
               status);
      log_update_outputs ("second",
                          completion_out,
                          enrollment_data_out,
                          output_value_out);
      if (status == CV_STATUS_UPDATE_AGAIN_EXPERIMENT)
        fprintf (stderr,
                 "[cv2-0x59-experiment] second 0x59 received; retry limit "
                 "reached\n");
      fprintf (stderr,
               "[cv2-0x59-experiment] passing second native status to "
               "existing Linux state machine\n");
    }

  if (status != CV_STATUS_BAD_CAPTURE)
    return status;

  attempt = atomic_fetch_add_explicit (&retry_attempt, 1, memory_order_relaxed)
            + 1;
  fprintf (stderr,
           "[cv2-0x89-experiment] 0x89 bad capture received; attempt=%u\n",
           attempt);
  fprintf (stderr,
           "[cv2-0x89-experiment] re-arming enrollment with command 0x8A; "
           "attempt=%u\n",
           attempt);

  rearm_status = resolver.enrollment_started ();
  if (rearm_status != CV_STATUS_SUCCESS)
    {
      fprintf (stderr,
               "[cv2-0x89-experiment] 0x8A failed with status 0x%x; "
               "attempt=%u\n",
               rearm_status,
               attempt);
      return fatalize_rearm_status (rearm_status);
    }

  fprintf (stderr,
           "[cv2-0x89-experiment] 0x8A completed successfully; attempt=%u\n",
           attempt);
  return CV_STATUS_BAD_CAPTURE;
}
