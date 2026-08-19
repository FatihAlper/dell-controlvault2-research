#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef OMIT_UPDATE
static unsigned int update_count;
static const void *first_enrollment_id;
static uint32_t first_auxiliary_input_size;
static const void *first_auxiliary_input;
static uint8_t *first_completion_out;
static void *first_enrollment_data_out;
static uint32_t *first_output_value_out;
#endif
static unsigned int enrollment_started_count;
static unsigned int capture_start_count;
static unsigned int capture_cancel_count;
static unsigned int discard_count;

static uint32_t
status_from_env (const char *name, uint32_t fallback)
{
  const char *value = getenv (name);
  char *end = NULL;
  unsigned long parsed;

  if (value == NULL)
    return fallback;
  parsed = strtoul (value, &end, 0);
  if (end == value || *end != '\0' || parsed > UINT32_MAX)
    {
      fprintf (stderr, "invalid mock status in %s\n", name);
      abort ();
    }
  return (uint32_t) parsed;
}

static int
optional_byte_from_env (const char *name, uint8_t *value)
{
  const char *configured = getenv (name);
  char *end = NULL;
  unsigned long parsed;

  if (configured == NULL)
    return 0;
  parsed = strtoul (configured, &end, 0);
  if (end == configured || *end != '\0' || parsed > UINT8_MAX)
    {
      fprintf (stderr, "invalid mock byte in %s\n", name);
      abort ();
    }
  *value = (uint8_t) parsed;
  return 1;
}

static int
optional_u32_from_env (const char *name, uint32_t *value)
{
  const char *configured = getenv (name);

  if (configured == NULL)
    return 0;
  *value = status_from_env (name, 0);
  return 1;
}

static int
buffer_is_zero (const void *buffer, size_t size)
{
  const unsigned char *bytes = buffer;

  if (buffer == NULL)
    return 0;
  for (size_t index = 0; index < size; index++)
    if (bytes[index] != 0)
      return 0;
  return 1;
}

#ifndef OMIT_REARM
uint32_t
cv_cmd_enrollment_started (void)
{
  uint32_t status = status_from_env ("MOCK_REARM_STATUS", 0);

  enrollment_started_count++;
  fprintf (stderr, "[mock-cv2] command 0x8A status=0x%x\n", status);
  return status;
}
#endif

uint32_t
cv_fingerprint_capture_start (uint32_t handle,
                              uint32_t capture_type,
                              uint32_t capture_flags,
                              void *capture_id,
                              void *unknown_zero,
                              void *unknown_zero_2)
{
  (void) handle;
  (void) capture_type;
  (void) capture_flags;
  (void) capture_id;
  (void) unknown_zero;
  (void) unknown_zero_2;
  capture_start_count++;
  fprintf (stderr, "[mock-cv2] command 0x66 status=0x0\n");
  return 0;
}

#ifndef OMIT_UPDATE
uint32_t
cv_fingerprint_update_enrollment (uint32_t handle,
                                  const void *enrollment_id,
                                  uint32_t auxiliary_input_size,
                                  const void *auxiliary_input,
                                  uint8_t *completion_out,
                                  void *enrollment_data_out,
                                  uint32_t *output_value_out)
{
  const char *completion_name;
  const char *output_byte_name;
  const char *output_value_name;
  uint8_t value;
  uint32_t status;

  (void) handle;

  update_count++;
  fprintf (stderr,
           "[mock-cv2] update input_zero=%s\n",
           buffer_is_zero (enrollment_id, 20) ? "yes" : "no");
  if (getenv ("MOCK_REQUIRE_ZERO_ENROLLMENT_ID") != NULL &&
      !buffer_is_zero (enrollment_id, 20))
    {
      fprintf (stderr, "[mock-cv2] required zero update input missing\n");
      abort ();
    }
  if (update_count == 1 && enrollment_id != NULL &&
      getenv ("MOCK_MUTATE_FIRST_ENROLLMENT_ID") != NULL)
    {
      ((unsigned char *) enrollment_id)[0] = 0x5a;
      fprintf (stderr, "[mock-cv2] mutated first update input\n");
    }
  if (update_count == 1)
    {
      status = status_from_env ("MOCK_FIRST_UPDATE_STATUS", 0x89);
      first_enrollment_id = enrollment_id;
      first_auxiliary_input_size = auxiliary_input_size;
      first_auxiliary_input = auxiliary_input;
      first_completion_out = completion_out;
      first_enrollment_data_out = enrollment_data_out;
      first_output_value_out = output_value_out;
      fprintf (stderr, "[mock-cv2] update argument identity=first\n");
    }
  else
    {
      status = status_from_env ("MOCK_SECOND_UPDATE_STATUS", 0);
      fprintf (
        stderr,
        "[mock-cv2] update argument identity=%s\n",
        enrollment_id == first_enrollment_id &&
            auxiliary_input_size == first_auxiliary_input_size &&
            auxiliary_input == first_auxiliary_input &&
            completion_out == first_completion_out &&
            enrollment_data_out == first_enrollment_data_out &&
            output_value_out == first_output_value_out
          ? "same"
          : "changed");
    }

  completion_name = update_count == 1 ? "MOCK_FIRST_COMPLETION"
                                      : "MOCK_SECOND_COMPLETION";
  output_byte_name = update_count == 1 ? "MOCK_FIRST_OUTPUT_BYTE"
                                       : "MOCK_SECOND_OUTPUT_BYTE";
  output_value_name = update_count == 1 ? "MOCK_FIRST_OUTPUT_VALUE"
                                        : "MOCK_SECOND_OUTPUT_VALUE";
  if (completion_out != NULL &&
      optional_byte_from_env (completion_name, &value))
    *completion_out = value;
  if (enrollment_data_out != NULL &&
      optional_byte_from_env (output_byte_name, &value))
    ((uint8_t *) enrollment_data_out)[0] = value;
  if (output_value_out != NULL)
    (void) optional_u32_from_env (output_value_name, output_value_out);

  fprintf (stderr, "[mock-cv2] command 0x6C status=0x%x\n", status);
  return status;
}
#else
uint32_t cv_fingerprint_update_enrollment (uint32_t,
                                           const void *,
                                           uint32_t,
                                           const void *,
                                           uint8_t *,
                                           void *,
                                           uint32_t *);
#endif

void
cv_fingerprint_capture_cancel (void)
{
  capture_cancel_count++;
  fprintf (stderr, "[mock-cv2] existing fatal capture-cancel path\n");
}

void
cv_fingerprint_discard_enrollment (void)
{
  discard_count++;
  fprintf (stderr, "[mock-cv2] existing fatal discard path\n");
}

/*
 * TOD-like caller kept inside the local-scope plugin.  Calls to the exported
 * update function use normal ELF symbol interposition, just like the
 * proprietary plugin.  Capture start itself is deliberately not interposed.
 */
int
mock_run_enrollment (void)
{
  uint32_t status;
  unsigned char enrollment_id[20] = { 0 };
  const void *enrollment_id_pointer = enrollment_id;
  unsigned char auxiliary_input[4] = { 0xa1, 0xa2, 0xa3, 0xa4 };
  const void *auxiliary_input_pointer = auxiliary_input;
  uint32_t auxiliary_input_size = sizeof auxiliary_input;
  uint8_t completion = 0x31;
  unsigned char enrollment_output[20];
  uint32_t output_value = 0x51525354;
  uint32_t sequential_updates = status_from_env (
    "MOCK_SEQUENTIAL_UPDATE_COUNT", 1);
  int defer_capture_completion =
    getenv ("MOCK_DEFER_CAPTURE_COMPLETION") != NULL;
  uint8_t initial_enrollment_id_byte;

  if (sequential_updates == 0 || sequential_updates > 16)
    {
      fprintf (stderr, "invalid MOCK_SEQUENTIAL_UPDATE_COUNT\n");
      abort ();
    }
  if (getenv ("MOCK_ZERO_AUXILIARY_INPUT") != NULL)
    {
      auxiliary_input_pointer = NULL;
      auxiliary_input_size = 0;
    }
  if (optional_byte_from_env ("MOCK_INITIAL_ENROLLMENT_ID_BYTE",
                              &initial_enrollment_id_byte))
    memset (enrollment_id,
            initial_enrollment_id_byte,
            sizeof enrollment_id);
  if (getenv ("MOCK_NULL_ENROLLMENT_ID") != NULL)
    enrollment_id_pointer = NULL;

  for (size_t index = 0; index < sizeof enrollment_output; index++)
    enrollment_output[index] = (unsigned char) (0x40 + index);

  status = cv_fingerprint_update_enrollment (
    1,
    enrollment_id_pointer,
    auxiliary_input_size,
    auxiliary_input_pointer,
    &completion,
    enrollment_output,
    &output_value);
  if (status != 0 && status != 0xa4 && status != 0x89)
    cv_fingerprint_capture_cancel ();
  fprintf (stderr, "[mock-tod] callback status=0x%x state=1\n", status);

  for (uint32_t index = 1;
       index < sequential_updates && status == 0;
       index++)
    {
      if (getenv ("MOCK_COPY_OUTPUT_TO_NEXT_ID") != NULL)
        memcpy (enrollment_id, enrollment_output, sizeof enrollment_id);
      else if (getenv ("MOCK_CHANGE_ENROLLMENT_ID_EACH_UPDATE") != NULL)
        memset (enrollment_id, (int) index, sizeof enrollment_id);
      (void) cv_fingerprint_capture_start (
        1, 2, 0x23, enrollment_id, NULL, NULL);
      status = cv_fingerprint_update_enrollment (
        1,
        enrollment_id_pointer,
        auxiliary_input_size,
        auxiliary_input_pointer,
        &completion,
        enrollment_output,
        &output_value);
      if (status != 0 && status != 0xa4 && status != 0x89)
        cv_fingerprint_capture_cancel ();
      fprintf (stderr, "[mock-tod] callback status=0x%x state=1\n", status);
    }

  if (status == 0x89)
    {
      (void) cv_fingerprint_capture_start (
        1, 2, 0x23, enrollment_id, NULL, NULL);
      if (!defer_capture_completion)
        {
          status = cv_fingerprint_update_enrollment (
            1,
            enrollment_id_pointer,
            auxiliary_input_size,
            auxiliary_input_pointer,
            &completion,
            enrollment_output,
            &output_value);
          if (status != 0 && status != 0xa4 && status != 0x89)
            cv_fingerprint_capture_cancel ();
          fprintf (stderr,
                   "[mock-tod] callback status=0x%x state=1\n",
                   status);
        }
    }
  else if (status != 0 && status != 0xa4 && status != 0x8f)
    {
      cv_fingerprint_discard_enrollment ();
    }

  fprintf (stderr,
           "[mock-tod] counters update=%u enrollment_started=%u capture=%u "
           "cancel=%u discard=%u\n",
           update_count,
           enrollment_started_count,
           capture_start_count,
           capture_cancel_count,
           discard_count);
  fprintf (stderr,
           "[mock-tod] final synthetic outputs completion=0x%02x "
           "output_byte=0x%02x output_value=0x%08x\n",
           (unsigned int) completion,
           (unsigned int) enrollment_output[0],
           output_value);
  printf ("final_status=0x%x\n", status);
  return 0;
}
