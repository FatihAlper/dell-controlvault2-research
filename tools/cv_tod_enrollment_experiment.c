/*
 * Explicitly opt-in hardware harness for the repository-local TOD build.
 * It does not store a local print, alter PAM, or install anything.  A
 * successful driver enrollment may nevertheless commit a template inside
 * ControlVault, which is why the runner requires an explicit confirmation.
 */

#include <glib-unix.h>
#include <glib.h>
#include <libfprint/fprint.h>
#include <dlfcn.h>

typedef int (*ForwardingReady) (void);

typedef struct
{
  GMainLoop *loop;
  GCancellable *cancellable;
  int exit_status;
} Experiment;

static gboolean
cancel_on_signal (gpointer user_data)
{
  Experiment *experiment = user_data;

  g_printerr ("signal received: cancelling enrollment cleanly\n");
  g_cancellable_cancel (experiment->cancellable);
  return G_SOURCE_CONTINUE;
}

static void
progress_cb (FpDevice *device,
             gint completed_stages,
             FpPrint *print,
             gpointer user_data,
             GError *error)
{
  (void) print;
  (void) user_data;
  if (error != NULL)
    g_printerr ("enrollment_progress=%d/%d retry=%s\n",
                completed_stages,
                fp_device_get_nr_enroll_stages (device),
                error->message);
  else
    g_print ("enrollment_progress=%d/%d accepted\n",
             completed_stages,
             fp_device_get_nr_enroll_stages (device));
}

static void
enroll_done (GObject *source_object,
             GAsyncResult *result,
             gpointer user_data)
{
  Experiment *experiment = user_data;
  FpDevice *device = FP_DEVICE (source_object);
  g_autoptr(FpPrint) enrolled = NULL;
  g_autoptr(GError) error = NULL;

  enrolled = fp_device_enroll_finish (device, result, &error);
  if (enrolled != NULL)
    {
      g_print ("enrollment_completed=yes (template may now exist in device)\n");
      experiment->exit_status = 0;
    }
  else
    {
      g_printerr ("enrollment_completed=no error=%s\n",
                  error != NULL ? error->message : "unknown");
      experiment->exit_status =
        g_error_matches (error, G_IO_ERROR, G_IO_ERROR_CANCELLED) ? 130 : 5;
    }
  g_main_loop_quit (experiment->loop);
}

int
main (void)
{
  g_autoptr(FpContext) context = NULL;
  g_autoptr(FpPrint) print_template = NULL;
  g_autoptr(GError) error = NULL;
  g_autoptr(GCancellable) cancellable = NULL;
  g_autoptr(GMainLoop) loop = NULL;
  GPtrArray *devices;
  FpDevice *device = NULL;
  Experiment experiment = { 0 };
  guint signal_source;
  guint i;
  ForwardingReady forwarding_ready;
  const char *dynamic_error;

  context = fp_context_new ();
  dlerror ();
  forwarding_ready = (ForwardingReady)
    dlsym (RTLD_DEFAULT, "cv2_0x89_forwarding_ready");
  dynamic_error = dlerror ();
  if (forwarding_ready == NULL || dynamic_error != NULL)
    {
      g_printerr ("forwarding readiness lookup failed: %s\n",
                  dynamic_error != NULL ? dynamic_error : "symbol not found");
      g_printerr ("refusing enrollment before device open\n");
      return 2;
    }
  if (!forwarding_ready ())
    {
      g_printerr ("local-scope forwarding readiness failed\n");
      g_printerr ("refusing enrollment before device open\n");
      return 2;
    }
  g_print ("local_scope_forwarding_ready=yes\n");

  fp_context_enumerate (context);
  devices = fp_context_get_devices (context);
  for (i = 0; i < devices->len; i++)
    {
      FpDevice *candidate = g_ptr_array_index (devices, i);

      if (g_strcmp0 (fp_device_get_driver (candidate), "broadcom") == 0)
        {
          device = candidate;
          break;
        }
    }
  if (device == NULL)
    {
      g_printerr ("no repository-local Broadcom device found\n");
      return 2;
    }

  cancellable = g_cancellable_new ();
  loop = g_main_loop_new (NULL, FALSE);
  experiment.loop = loop;
  experiment.cancellable = cancellable;
  experiment.exit_status = 5;

  signal_source = g_unix_signal_add (SIGINT, cancel_on_signal, &experiment);
  if (!fp_device_open_sync (device, cancellable, &error))
    {
      g_printerr ("device open failed: %s\n", error->message);
      g_source_remove (signal_source);
      return 3;
    }
  g_print ("device_opened=yes driver=%s stages=%d finger=right-index\n",
           fp_device_get_driver (device),
           fp_device_get_nr_enroll_stages (device));

  print_template = fp_print_new (device);
  fp_print_set_finger (print_template, FP_FINGER_RIGHT_INDEX);
  fp_device_enroll (device,
                    g_steal_pointer (&print_template),
                    cancellable,
                    progress_cb,
                    NULL,
                    NULL,
                    enroll_done,
                    &experiment);
  g_main_loop_run (loop);

  g_clear_error (&error);
  if (!fp_device_close_sync (device, NULL, &error))
    {
      g_printerr ("device close failed: %s\n", error->message);
      experiment.exit_status = 6;
    }
  else
    {
      g_print ("device_closed=yes\n");
    }
  g_source_remove (signal_source);
  return experiment.exit_status;
}
