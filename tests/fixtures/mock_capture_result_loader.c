#define _GNU_SOURCE

#include <dlfcn.h>
#include <gmodule.h>
#include <stdio.h>

typedef int (*probe_fn) (void);

int
main (int argc, char **argv)
{
  GModule *module;
  probe_fn ready;
  probe_fn run;
  probe_fn complete;

  if (argc != 2)
    return 64;
  module = g_module_open (argv[1], G_MODULE_BIND_LAZY | G_MODULE_BIND_LOCAL);
  if (module == NULL)
    {
      fprintf (stderr, "mock plugin load failed: %s\n", g_module_error ());
      return 2;
    }
  ready = (probe_fn) dlsym (RTLD_DEFAULT, "cv2_capture_result_probe_ready");
  complete = (probe_fn) dlsym (RTLD_DEFAULT,
                               "cv2_capture_result_probe_complete");
  if (ready == NULL || complete == NULL || !ready ())
    return 3;
  if (!g_module_symbol (module,
                        "mock_run_capture_result",
                        (gpointer *) &run))
    return 4;
  if (run () != 0)
    return 5;
  return complete () ? 0 : 6;
}
