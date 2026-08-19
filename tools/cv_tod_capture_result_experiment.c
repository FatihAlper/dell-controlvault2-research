/*
 * Hardware trigger for the capture-only CaptureGetResult interposer.
 * A libfprint enrollment request is used only to obtain one completed normal
 * capture.  The preloaded boundary blocks UpdateEnrollment before it reaches
 * the proprietary DSO, performs one metadata-only CaptureGetResult probe, and
 * returns a fatal status.  A successful enrollment is therefore a boundary
 * violation, not success.
 */

#include <dlfcn.h>
#include <glib-unix.h>
#include <glib.h>
#include <libfprint/fprint.h>

typedef int (*ProbeFunction) (void);

typedef struct
{
  GMainLoop *loop;
  GCancellable *cancellable;
  ProbeFunction complete;
  int exit_status;
} Experiment;

static gboolean
cancel_on_signal (gpointer user_data)
{
  Experiment *experiment = user_data;

  g_printerr ("signal received: cancelling capture-only probe\n");
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
  (void) device;
  (void) completed_stages;
  (void) print;
  (void) user_data;
  (void) error;
  g_printerr ("boundary_violation=enrollment progress escaped probe\n");
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
      g_printerr ("boundary_violation=enrollment unexpectedly completed\n");
      experiment->exit_status = 7;
    }
  else if (experiment->complete ())
    {
      g_print ("capture_result_probe_completed=yes\n");
      g_print ("enrollment_completed=no\n");
      experiment->exit_status = 0;
    }
  else
    {
      g_printerr ("capture_result_probe_completed=no error=%s\n",
                  error != NULL ? error->message : "unknown");
      experiment->exit_status = 5;
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
  ProbeFunction ready;
  ProbeFunction complete;
  const char *dynamic_error;
  guint signal_source;
  guint i;

  context = fp_context_new ();
  dlerror ();
  ready = (ProbeFunction) dlsym (RTLD_DEFAULT,
                                 "cv2_capture_result_probe_ready");
  complete = (ProbeFunction) dlsym (RTLD_DEFAULT,
                                    "cv2_capture_result_probe_complete");
  dynamic_error = dlerror ();
  if (ready == NULL || complete == NULL || dynamic_error != NULL || !ready ())
    {
      g_printerr ("capture-only readiness failed before device enumeration\n");
      return 2;
    }
  g_print ("capture_only_boundary_ready=yes\n");

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
  experiment.complete = complete;
  experiment.exit_status = 5;
  signal_source = g_unix_signal_add (SIGINT, cancel_on_signal, &experiment);

  if (!fp_device_open_sync (device, cancellable, &error))
    {
      g_printerr ("device open failed: %s\n", error->message);
      g_source_remove (signal_source);
      return 3;
    }
  g_print ("device_opened=yes driver=%s\n", fp_device_get_driver (device));

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
    g_print ("device_closed=yes\n");
  g_source_remove (signal_source);
  return experiment.exit_status;
}
