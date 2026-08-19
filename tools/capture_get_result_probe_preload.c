/*
 * Capture-only evidence interposer for the pinned BCM5880 TOD driver.
 *
 * The normal TOD enrollment flow is allowed to open the device and complete
 * one CaptureStart.  At the first UpdateEnrollment boundary this interposer
 * does NOT forward UpdateEnrollment.  It instead invokes exactly one
 * cv_fingerprint_capture_get_result(handle, 1, capture_id, &size, buffer),
 * records only status and length, wipes the private buffer, and returns a
 * fatal experimental status so the unchanged TOD flow performs cleanup.
 *
 * No payload byte, capture ID, pointer, digest, template, or score is logged.
 * CreateTemplate and CommitEnrollment are never resolved or called here.
 */

#define _GNU_SOURCE

#include <dlfcn.h>
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

#define CV2_TARGET_ENV "CV2_CAPTURE_RESULT_TARGET_PATH"
#define CV2_CAPTURE_SELECTOR 1u
#define CV2_CAPTURE_CAPACITY 0x17000u
#define CV2_EXPERIMENT_FAILURE 0x100003u

typedef uint32_t (*capture_get_result_fn) (uint32_t handle,
                                           uint8_t selector,
                                           const void *capture_id,
                                           uint32_t *size,
                                           void *output);

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
  capture_get_result_fn capture_get_result;
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
static atomic_uint intercepted_updates = 0;
static atomic_uint native_capture_result_calls = 0;
static atomic_bool result_metadata_valid = false;

static void
resolver_failure (const char *format, ...)
{
  va_list args;

  va_start (args, format);
  vsnprintf (resolver.failure, sizeof resolver.failure, format, args);
  va_end (args);
  fprintf (stderr, "[cv2-capture-result-resolver] failed: %s\n",
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
      resolver_failure ("target symbol %s resolved to this interposer", name);
      return false;
    }
  memset (&owner, 0, sizeof owner);
  if (dladdr (address, &owner) == 0 || owner.dli_fname == NULL ||
      !identity_from_path (owner.dli_fname, &owner_identity))
    {
      resolver_failure ("could not identify owner of %s", name);
      return false;
    }
  if (strcmp (owner_identity.path, target->path) != 0 ||
      owner_identity.device != target->device ||
      owner_identity.inode != target->inode)
    {
      resolver_failure ("symbol %s belongs to unexpected DSO", name);
      return false;
    }
  fprintf (stderr,
           "[cv2-capture-result-resolver] target-owned symbol=%s\n",
           name);
  return true;
}

static void
initialize_resolver (void)
{
  const char *configured_path = getenv (CV2_TARGET_ENV);
  LoadedSearch search = { 0 };
  void *capture_address;
  void *update_address;
  const char *dynamic_error;

  if (!identity_from_path (configured_path, &search.expected))
    {
      resolver_failure ("invalid or missing %s", CV2_TARGET_ENV);
      return;
    }
  dl_iterate_phdr (find_loaded_target, &search);
  if (!search.found)
    {
      resolver_failure ("expected target is not loaded; refusing lookup");
      return;
    }

  dlerror ();
  resolver.handle = dlopen (search.expected.path, RTLD_LAZY | RTLD_NOLOAD);
  dynamic_error = dlerror ();
  if (resolver.handle == NULL || dynamic_error != NULL)
    {
      resolver.handle = NULL;
      resolver_failure ("RTLD_NOLOAD acquisition failed");
      return;
    }

  dlerror ();
  capture_address = dlsym (resolver.handle,
                           "cv_fingerprint_capture_get_result");
  dynamic_error = dlerror ();
  if (dynamic_error != NULL)
    capture_address = NULL;
  if (!symbol_owned_by_target (capture_address,
                               "cv_fingerprint_capture_get_result",
                               &search.expected,
                               NULL))
    return;

  /* Validate the interception boundary exists in the same exact target. */
  dlerror ();
  update_address = dlsym (resolver.handle,
                          "cv_fingerprint_update_enrollment");
  dynamic_error = dlerror ();
  if (dynamic_error != NULL)
    update_address = NULL;
  if (!symbol_owned_by_target (update_address,
                               "cv_fingerprint_update_enrollment",
                               &search.expected,
                               (void *) cv_fingerprint_update_enrollment))
    return;

  resolver.capture_get_result = (capture_get_result_fn) capture_address;
  resolver.ready = true;
  fprintf (stderr,
           "[cv2-capture-result-resolver] capture-only boundary ready\n");
}

static bool
capture_probe_ready (void)
{
  int status = pthread_once (&resolver_once, initialize_resolver);

  if (status != 0)
    {
      resolver_failure ("pthread_once failed: %s", strerror (status));
      return false;
    }
  return resolver.ready;
}

int
cv2_capture_result_probe_ready (void)
{
  if (!capture_probe_ready ())
    {
      fprintf (stderr,
               "[cv2-capture-result] refusing before device open: %s\n",
               resolver.failure[0] != '\0' ? resolver.failure : "not ready");
      return 0;
    }
  return 1;
}

int
cv2_capture_result_probe_complete (void)
{
  return atomic_load_explicit (&intercepted_updates, memory_order_relaxed) >= 1 &&
         atomic_load_explicit (&native_capture_result_calls,
                               memory_order_relaxed) == 1 &&
         atomic_load_explicit (&result_metadata_valid, memory_order_relaxed);
}

static void
secure_wipe (void *buffer, size_t size)
{
  volatile unsigned char *bytes = buffer;

  while (size > 0)
    {
      *bytes++ = 0;
      size--;
    }
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
  unsigned int update_number;
  unsigned char *buffer;
  uint32_t result_size = CV2_CAPTURE_CAPACITY;
  uint32_t status;

  (void) auxiliary_input_size;
  (void) auxiliary_input;
  (void) completion_out;
  (void) enrollment_data_out;
  (void) output_value_out;

  if (!capture_probe_ready ())
    return CV2_EXPERIMENT_FAILURE;

  update_number = atomic_fetch_add_explicit (&intercepted_updates,
                                              1,
                                              memory_order_relaxed)
                  + 1;
  if (update_number != 1)
    {
      fprintf (stderr,
               "[cv2-capture-result] additional UpdateEnrollment blocked "
               "call=%u\n",
               update_number);
      return CV2_EXPERIMENT_FAILURE;
    }
  if (handle == 0 || enrollment_id == NULL)
    {
      fprintf (stderr,
               "[cv2-capture-result] invalid capture boundary; native call "
               "blocked\n");
      return CV2_EXPERIMENT_FAILURE;
    }

  buffer = calloc (1, CV2_CAPTURE_CAPACITY);
  if (buffer == NULL)
    {
      fprintf (stderr, "[cv2-capture-result] private allocation failed\n");
      return CV2_EXPERIMENT_FAILURE;
    }

  atomic_fetch_add_explicit (&native_capture_result_calls,
                             1,
                             memory_order_relaxed);
  status = resolver.capture_get_result (handle,
                                        CV2_CAPTURE_SELECTOR,
                                        enrollment_id,
                                        &result_size,
                                        buffer);
  atomic_store_explicit (&result_metadata_valid,
                         result_size <= CV2_CAPTURE_CAPACITY,
                         memory_order_relaxed);
  fprintf (stderr,
           "[cv2-capture-result] native_status=0x%x selector=%u "
           "returned_size=%u capacity=%u size_valid=%s payload_logged=no\n",
           status,
           CV2_CAPTURE_SELECTOR,
           result_size,
           CV2_CAPTURE_CAPACITY,
           result_size <= CV2_CAPTURE_CAPACITY ? "yes" : "no");
  secure_wipe (buffer, CV2_CAPTURE_CAPACITY);
  free (buffer);
  fprintf (stderr,
           "[cv2-capture-result] payload_wiped=yes "
           "UpdateEnrollment_forwarded=no CreateTemplate_called=no "
           "CommitEnrollment_called=no native_calls=%u\n",
           atomic_load_explicit (&native_capture_result_calls,
                                 memory_order_relaxed));
  return CV2_EXPERIMENT_FAILURE;
}
