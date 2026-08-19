#ifndef CV2_BCM5880_LINUX_ABI_ADAPTER_H
#define CV2_BCM5880_LINUX_ABI_ADAPTER_H

#include "bcm5880_enrollment_coordinator.h"

#include <stdbool.h>
#include <stdint.h>

#define CV2_BCM5880_NATIVE_INVALID_PARAMETER 0x47u
#define CV2_BCM5880_NATIVE_COMMIT_MAX_OUTPUT 0x18000u

/*
 * Recovered x86-64 SysV ABI of cv_fingerprint_capture_get_result at RVA
 * 0x258d0 in the pinned probe DSO. This is a type only: the mock adapter has
 * no symbol resolver and cannot load the proprietary DSO.
 */
typedef uint32_t (*Cv2Bcm5880CaptureGetResultNativeMock) (
  uint32_t handle,
  uint8_t result_selector,
  const uint8_t capture_id[CV2_BCM5880_ENROLLMENT_ID_SIZE],
  uint32_t *feature_size_inout,
  uint8_t *feature_out);

/*
 * Recovered x86-64 SysV ABI of cv_fingerprint_create_template at RVA 0x26d10:
 * four size/pointer input pairs followed by a capacity/size pointer and an
 * output buffer.
 */
typedef uint32_t (*Cv2Bcm5880CreateTemplateNativeMock) (
  uint32_t handle,
  uint32_t feature0_size,
  const uint8_t *feature0,
  uint32_t feature1_size,
  const uint8_t *feature1,
  uint32_t feature2_size,
  const uint8_t *feature2,
  uint32_t feature3_size,
  const uint8_t *feature3,
  uint32_t *template_size_inout,
  uint8_t *template_out);

/*
 * Recovered x86-64 SysV ABI of cv_fingerprint_commit_enrollment at RVA
 * 0x266a0.  The 20-byte token and the two optional blobs are inputs.  The
 * final three arguments are an output size/buffer pair and a four-byte
 * result.  A zero-sized/null buffer is valid when result_out is present.
 */
typedef uint32_t (*Cv2Bcm5880CommitEnrollmentNativeMock) (
  uint32_t handle,
  const uint8_t token[CV2_BCM5880_ENROLLMENT_ID_SIZE],
  uint32_t input0_size,
  const uint8_t *input0,
  uint32_t input1_size,
  const uint8_t *input1,
  uint32_t *output_size_inout,
  uint8_t *output,
  uint32_t *result_out);

typedef enum
{
  CV2_BCM5880_ABI_ERROR_NONE = 0,
  CV2_BCM5880_ABI_ERROR_INVALID_ARGUMENT,
  CV2_BCM5880_ABI_ERROR_MOCK_MODE_REQUIRED,
} Cv2Bcm5880AbiError;

typedef struct
{
  Cv2Bcm5880ExecutionMode mode;
  Cv2Bcm5880CaptureGetResultNativeMock capture_get_result;
  Cv2Bcm5880CreateTemplateNativeMock create_template;
  Cv2Bcm5880CommitEnrollmentNativeMock commit_enrollment;
} Cv2Bcm5880LinuxAbiMockConfig;

typedef struct
{
  Cv2Bcm5880CaptureGetResultNativeMock capture_get_result;
  Cv2Bcm5880CreateTemplateNativeMock create_template;
  Cv2Bcm5880CommitEnrollmentNativeMock commit_enrollment;
  bool initialized;
} Cv2Bcm5880LinuxAbiMock;

bool
cv2_bcm5880_linux_abi_mock_init (
  Cv2Bcm5880LinuxAbiMock *adapter,
  const Cv2Bcm5880LinuxAbiMockConfig *config,
  Cv2Bcm5880AbiError *error_out);

void
cv2_bcm5880_linux_abi_mock_clear (Cv2Bcm5880LinuxAbiMock *adapter);

uint32_t
cv2_bcm5880_linux_abi_mock_capture_get_result (
  Cv2Bcm5880LinuxAbiMock *adapter,
  uint32_t handle,
  uint8_t result_selector,
  const uint8_t capture_id[CV2_BCM5880_ENROLLMENT_ID_SIZE],
  uint32_t *feature_size_inout,
  uint8_t *feature_out);

/* Matches Cv2Bcm5880CreateTemplateMock and can be injected into the
 * coordinator's mock operations. */
uint32_t
cv2_bcm5880_linux_abi_mock_create_template (
  void *user_data,
  uint32_t handle,
  const uint32_t feature_sizes[CV2_BCM5880_TEMPLATE_FEATURES],
  const uint8_t *const features[CV2_BCM5880_TEMPLATE_FEATURES],
  uint32_t *template_size_inout,
  uint8_t *template_out);

uint32_t
cv2_bcm5880_linux_abi_mock_commit_enrollment (
  Cv2Bcm5880LinuxAbiMock *adapter,
  uint32_t handle,
  const uint8_t token[CV2_BCM5880_ENROLLMENT_ID_SIZE],
  uint32_t input0_size,
  const uint8_t *input0,
  uint32_t input1_size,
  const uint8_t *input1,
  uint32_t *output_size_inout,
  uint8_t *output,
  uint32_t *result_out);

const char *
cv2_bcm5880_abi_error_name (Cv2Bcm5880AbiError error);

#endif
