#ifndef CV2_BCM5880_GENERIC_COMMIT_SEQUENCE_MOCK_ONLY
#error "BCM5880 generic commit sequence is mock-only; define CV2_BCM5880_GENERIC_COMMIT_SEQUENCE_MOCK_ONLY"
#endif

#include "bcm5880_generic_commit_sequence.h"

#include <stddef.h>
#include <string.h>

static const uint8_t commit_input0[CV2_BCM5880_GENERIC_COMMIT_INPUT0_SIZE] = {
  0x00, 0x00, 0x04, 0x00, 0x04, 0x00, 0x00, 0x00
};

static const uint8_t commit_input1[CV2_BCM5880_GENERIC_COMMIT_INPUT1_SIZE] = {
  0x01, 0x01, 0xff, 0x00, 0x00, 0x00, 0x0d, 0x00, 0x0c,
  'B', 'r', 'o', 'a', 'd', 'c', 'o', 'm', 'W', 'B', 'F', '\0'
};

static void
secure_clear (void *memory, size_t size)
{
  volatile uint8_t *bytes = memory;

  while (size-- > 0)
    *bytes++ = 0;
}

uint32_t
cv2_bcm5880_generic_commit_mock_run (
  Cv2Bcm5880LinuxAbiMock *adapter,
  uint32_t handle,
  const uint8_t token[CV2_BCM5880_ENROLLMENT_ID_SIZE],
  uint8_t phase1_output[CV2_BCM5880_GENERIC_COMMIT_PHASE1_CAPACITY],
  Cv2Bcm5880GenericCommitSnapshot *snapshot)
{
  uint32_t phase1_size = CV2_BCM5880_GENERIC_COMMIT_PHASE1_CAPACITY;
  uint32_t phase2_size = 0;
  uint32_t status;

  if (snapshot != NULL)
    memset (snapshot, 0, sizeof *snapshot);
  if (adapter == NULL || token == NULL || phase1_output == NULL ||
      snapshot == NULL)
    return CV2_BCM5880_NATIVE_INVALID_PARAMETER;

  memset (phase1_output, 0, CV2_BCM5880_GENERIC_COMMIT_PHASE1_CAPACITY);
  status = cv2_bcm5880_linux_abi_mock_commit_enrollment (
    adapter,
    handle,
    token,
    sizeof commit_input0,
    commit_input0,
    sizeof commit_input1,
    commit_input1,
    &phase1_size,
    phase1_output,
    &snapshot->phase1_result);
  snapshot->phase1_status = status;
  snapshot->phase1_output_size = phase1_size;
  if (status != 0 || phase1_size == 0)
    {
      secure_clear (phase1_output,
                    CV2_BCM5880_GENERIC_COMMIT_PHASE1_CAPACITY);
      snapshot->phase1_output_size = 0;
      return status != 0 ? status : CV2_BCM5880_NATIVE_INVALID_PARAMETER;
    }
  snapshot->phase1_complete = true;

  status = cv2_bcm5880_linux_abi_mock_commit_enrollment (
    adapter,
    handle,
    token,
    sizeof commit_input0,
    commit_input0,
    sizeof commit_input1,
    commit_input1,
    &phase2_size,
    NULL,
    &snapshot->phase2_result);
  snapshot->phase2_status = status;
  if (status != 0 || phase2_size != 0)
    {
      secure_clear (phase1_output,
                    CV2_BCM5880_GENERIC_COMMIT_PHASE1_CAPACITY);
      snapshot->phase1_output_size = 0;
      return status != 0 ? status : CV2_BCM5880_NATIVE_INVALID_PARAMETER;
    }
  snapshot->phase2_complete = true;
  return 0;
}
