#define _GNU_SOURCE

#include <dlfcn.h>
#include <gmodule.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef int (*readiness_fn) (void);
typedef int (*run_fn) (void);

static void
fatal_dynamic_error (const char *operation)
{
  const char *error = dlerror ();

  fprintf (stderr,
           "[mock-loader] %s failed: %s\n",
           operation,
           error != NULL ? error : "unknown error");
  exit (2);
}

int
main (int argc, char **argv)
{
  GModule *module = NULL;
  readiness_fn readiness;
  run_fn run;
  const char *mode;

  if (argc != 3)
    {
      fprintf (stderr,
               "usage: %s PLUGIN ready-success|ready-failure|"
               "run-without-ready|no-load-ready-failure\n",
               argv[0]);
      return 64;
    }
  mode = argv[2];

  if (strcmp (mode, "no-load-ready-failure") != 0)
    {
      module = g_module_open (argv[1],
                              G_MODULE_BIND_LAZY | G_MODULE_BIND_LOCAL);
      if (module == NULL)
        {
          fprintf (stderr,
                   "[mock-loader] G_MODULE_BIND_LOCAL plugin load failed: %s\n",
                   g_module_error ());
          return 2;
        }
      fprintf (stderr,
               "[mock-loader] plugin loaded with G_MODULE_BIND_LOCAL\n");
    }

  if (strcmp (mode, "run-without-ready") != 0)
    {
      dlerror ();
      readiness = (readiness_fn) dlsym (RTLD_DEFAULT,
                                        "cv2_0x89_forwarding_ready");
      if (readiness == NULL)
        fatal_dynamic_error ("readiness lookup");
      if (readiness () == 0)
        {
          fprintf (stderr, "[mock-loader] readiness=failed\n");
          if (strcmp (mode, "no-load-ready-failure") == 0)
            {
              void *unexpected;

              dlerror ();
              unexpected = dlopen (argv[1], RTLD_LAZY | RTLD_NOLOAD);
              if (unexpected != NULL)
                {
                  fprintf (stderr,
                           "[mock-loader] target was unexpectedly loaded\n");
                  return 5;
                }
              fprintf (stderr,
                       "[mock-loader] target remains unloaded after readiness\n");
              return 0;
            }
          return strcmp (mode, "ready-failure") == 0 ? 0 : 3;
        }
      fprintf (stderr, "[mock-loader] readiness=ready\n");
      if (strcmp (mode, "ready-failure") == 0)
        return 4;
    }

  if (!g_module_symbol (module, "mock_run_enrollment", (gpointer *) &run))
    {
      fprintf (stderr,
               "[mock-loader] mock enrollment lookup failed: %s\n",
               g_module_error ());
      return 2;
    }
  return run ();
}
