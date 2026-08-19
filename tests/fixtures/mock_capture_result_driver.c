#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define MOCK_CAPACITY 0x17000u
#define MOCK_EXPERIMENT_FAILURE 0x100003u

uint32_t cv_fingerprint_update_enrollment (uint32_t handle,
                                           const void *enrollment_id,
                                           uint32_t auxiliary_input_size,
                                           const void *auxiliary_input,
                                           uint8_t *completion_out,
                                           void *enrollment_data_out,
                                           uint32_t *output_value_out);

static const unsigned char capture_id[20] = {
  0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19,
  0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29,
};

uint32_t
cv_fingerprint_capture_get_result (uint32_t handle,
                                   uint8_t selector,
                                   const void *provided_capture_id,
                                   uint32_t *size,
                                   void *output)
{
  if (handle != 0x12345678u || selector != 1 ||
      provided_capture_id == NULL ||
      memcmp (provided_capture_id, capture_id, sizeof capture_id) != 0 ||
      size == NULL || *size != MOCK_CAPACITY || output == NULL)
    return 0xdead0001u;
  memset (output, 0xa5, 32);
  *size = 32;
  fprintf (stderr,
           "[mock-capture-driver] ABI arguments valid; payload remains private\n");
  return 0;
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
  (void) handle;
  (void) enrollment_id;
  (void) auxiliary_input_size;
  (void) auxiliary_input;
  (void) completion_out;
  (void) enrollment_data_out;
  (void) output_value_out;
  fprintf (stderr, "[mock-capture-driver] ERROR original update was called\n");
  return 0xdead0002u;
}

int
mock_run_capture_result (void)
{
  uint8_t completion = 0;
  unsigned char enrollment_output[20] = { 0 };
  uint32_t output_value = 0;
  uint32_t status;
  uint32_t second_status;

  status = cv_fingerprint_update_enrollment (0x12345678u,
                                             capture_id,
                                             0,
                                             NULL,
                                             &completion,
                                             enrollment_output,
                                             &output_value);
  fprintf (stderr, "[mock-capture-driver] boundary_status=0x%x\n", status);
  second_status = cv_fingerprint_update_enrollment (0x12345678u,
                                                    capture_id,
                                                    0,
                                                    NULL,
                                                    &completion,
                                                    enrollment_output,
                                                    &output_value);
  fprintf (stderr,
           "[mock-capture-driver] second_boundary_status=0x%x\n",
           second_status);
  return status == MOCK_EXPERIMENT_FAILURE &&
         second_status == MOCK_EXPERIMENT_FAILURE
           ? 0
           : 9;
}
