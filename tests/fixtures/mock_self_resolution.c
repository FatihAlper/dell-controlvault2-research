#define _GNU_SOURCE

#include <dlfcn.h>
#include <stdint.h>

/*
 * Test-only IFUNC whose resolved address is the preloaded wrapper.  It lets
 * the ownership validator exercise its explicit recursion guard.
 */
typedef uint32_t (*update_fn) (uint32_t,
                               void *,
                               uint32_t,
                               void *,
                               void *,
                               void *,
                               void *);

static update_fn
resolve_update_to_preload (void)
{
  return (update_fn)
    dlsym (RTLD_DEFAULT, "cv_fingerprint_update_enrollment");
}

uint32_t cv_fingerprint_update_enrollment (uint32_t,
                                           void *,
                                           uint32_t,
                                           void *,
                                           void *,
                                           void *,
                                           void *)
  __attribute__ ((ifunc ("resolve_update_to_preload")));

uint32_t
cv_cmd_enrollment_started (void)
{
  return 0;
}
