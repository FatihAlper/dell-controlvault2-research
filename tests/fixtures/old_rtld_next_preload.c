#define _GNU_SOURCE

#include <dlfcn.h>
#include <stdint.h>
#include <stdio.h>

#define CV_STATUS_EXPERIMENT_FAILURE 0x100003u

typedef uint32_t (*update_fn) (uint32_t,
                               void *,
                               uint32_t,
                               void *,
                               void *,
                               void *,
                               void *);

uint32_t
cv_fingerprint_update_enrollment (uint32_t handle,
                                  void *capture_id,
                                  uint32_t unknown_zero,
                                  void *complete_out,
                                  void *template_out,
                                  void *unknown_out,
                                  void *unknown_out_2)
{
  update_fn real_update;
  const char *error;

  dlerror ();
  real_update = (update_fn) dlsym (RTLD_NEXT,
                                   "cv_fingerprint_update_enrollment");
  error = dlerror ();
  if (real_update == NULL || error != NULL)
    {
      fprintf (stderr,
               "[old-resolver] RTLD_NEXT failed for local-scope target: %s\n",
               error != NULL ? error : "symbol not found");
      return CV_STATUS_EXPERIMENT_FAILURE;
    }
  return real_update (handle,
                      capture_id,
                      unknown_zero,
                      complete_out,
                      template_out,
                      unknown_out,
                      unknown_out_2);
}
