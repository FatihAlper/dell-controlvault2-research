#ifndef CV2_BCM5880_GENERIC_COMMIT_SEQUENCE_H
#define CV2_BCM5880_GENERIC_COMMIT_SEQUENCE_H

#include "bcm5880_linux_abi_adapter.h"

#include <stdbool.h>
#include <stdint.h>

#define CV2_BCM5880_GENERIC_COMMIT_PHASE1_CAPACITY 0x800u
#define CV2_BCM5880_GENERIC_COMMIT_INPUT0_SIZE 8u
#define CV2_BCM5880_GENERIC_COMMIT_INPUT1_SIZE 21u

/*
 * Mock-only reconstruction of the two generic command-0x6e calls observed
 * on the Windows A21 0a5c:5833 path.  It has no loader or transport and can
 * call only the mock callback injected into Cv2Bcm5880LinuxAbiMock.
 */
typedef struct
{
  uint32_t phase1_status;
  uint32_t phase1_result;
  uint32_t phase1_output_size;
  uint32_t phase2_status;
  uint32_t phase2_result;
  bool phase1_complete;
  bool phase2_complete;
} Cv2Bcm5880GenericCommitSnapshot;

uint32_t
cv2_bcm5880_generic_commit_mock_run (
  Cv2Bcm5880LinuxAbiMock *adapter,
  uint32_t handle,
  const uint8_t token[CV2_BCM5880_ENROLLMENT_ID_SIZE],
  uint8_t phase1_output[CV2_BCM5880_GENERIC_COMMIT_PHASE1_CAPACITY],
  Cv2Bcm5880GenericCommitSnapshot *snapshot);

#endif
