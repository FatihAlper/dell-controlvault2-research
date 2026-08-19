#ifndef CV2_BCM5880_LINUX_ABI_ADAPTER_MOCK_ONLY
#error "BCM5880 Linux ABI adapter is mock-only; define CV2_BCM5880_LINUX_ABI_ADAPTER_MOCK_ONLY"
#endif

#include "bcm5880_linux_abi_adapter.h"

#include <stddef.h>
#include <string.h>

static void
secure_clear (void *memory, size_t size)
{
  volatile uint8_t *bytes = memory;

  while (size-- > 0)
    *bytes++ = 0;
}

bool
cv2_bcm5880_linux_abi_mock_init (
  Cv2Bcm5880LinuxAbiMock *adapter,
  const Cv2Bcm5880LinuxAbiMockConfig *config,
  Cv2Bcm5880AbiError *error_out)
{
  Cv2Bcm5880AbiError error = CV2_BCM5880_ABI_ERROR_NONE;

  if (adapter == NULL || config == NULL ||
      config->capture_get_result == NULL || config->create_template == NULL ||
      config->commit_enrollment == NULL)
    error = CV2_BCM5880_ABI_ERROR_INVALID_ARGUMENT;
  else if (config->mode != CV2_BCM5880_EXECUTION_MOCK_ONLY)
    error = CV2_BCM5880_ABI_ERROR_MOCK_MODE_REQUIRED;

  if (error != CV2_BCM5880_ABI_ERROR_NONE)
    {
      if (adapter != NULL)
        memset (adapter, 0, sizeof *adapter);
      if (error_out != NULL)
        *error_out = error;
      return false;
    }

  memset (adapter, 0, sizeof *adapter);
  adapter->capture_get_result = config->capture_get_result;
  adapter->create_template = config->create_template;
  adapter->commit_enrollment = config->commit_enrollment;
  adapter->initialized = true;
  if (error_out != NULL)
    *error_out = CV2_BCM5880_ABI_ERROR_NONE;
  return true;
}

void
cv2_bcm5880_linux_abi_mock_clear (Cv2Bcm5880LinuxAbiMock *adapter)
{
  if (adapter != NULL)
    secure_clear (adapter, sizeof *adapter);
}

uint32_t
cv2_bcm5880_linux_abi_mock_capture_get_result (
  Cv2Bcm5880LinuxAbiMock *adapter,
  uint32_t handle,
  uint8_t result_selector,
  const uint8_t capture_id[CV2_BCM5880_ENROLLMENT_ID_SIZE],
  uint32_t *feature_size_inout,
  uint8_t *feature_out)
{
  uint32_t capacity;
  uint32_t status;

  if (adapter == NULL || !adapter->initialized ||
      adapter->capture_get_result == NULL || capture_id == NULL ||
      feature_size_inout == NULL || feature_out == NULL)
    return CV2_BCM5880_NATIVE_INVALID_PARAMETER;

  capacity = *feature_size_inout;
  if (capacity == 0 || capacity > CV2_BCM5880_FEATURE_CAPACITY)
    return CV2_BCM5880_NATIVE_INVALID_PARAMETER;

  status = adapter->capture_get_result (handle,
                                        result_selector,
                                        capture_id,
                                        feature_size_inout,
                                        feature_out);
  if (*feature_size_inout > capacity ||
      *feature_size_inout > CV2_BCM5880_FEATURE_CAPACITY)
    {
      secure_clear (feature_out, capacity);
      *feature_size_inout = 0;
      return CV2_BCM5880_NATIVE_INVALID_PARAMETER;
    }
  return status;
}

uint32_t
cv2_bcm5880_linux_abi_mock_create_template (
  void *user_data,
  uint32_t handle,
  const uint32_t feature_sizes[CV2_BCM5880_TEMPLATE_FEATURES],
  const uint8_t *const features[CV2_BCM5880_TEMPLATE_FEATURES],
  uint32_t *template_size_inout,
  uint8_t *template_out)
{
  Cv2Bcm5880LinuxAbiMock *adapter = user_data;
  uint32_t capacity;
  uint32_t status;

  if (adapter == NULL || !adapter->initialized ||
      adapter->create_template == NULL || feature_sizes == NULL ||
      features == NULL || template_size_inout == NULL || template_out == NULL)
    return CV2_BCM5880_NATIVE_INVALID_PARAMETER;

  for (unsigned int index = 0; index < CV2_BCM5880_TEMPLATE_FEATURES;
       index++)
    if (feature_sizes[index] == 0 ||
        feature_sizes[index] > CV2_BCM5880_FEATURE_CAPACITY ||
        features[index] == NULL)
      return CV2_BCM5880_NATIVE_INVALID_PARAMETER;

  capacity = *template_size_inout;
  if (capacity == 0 || capacity > CV2_BCM5880_TEMPLATE_CAPACITY)
    return CV2_BCM5880_NATIVE_INVALID_PARAMETER;

  status = adapter->create_template (handle,
                                     feature_sizes[0],
                                     features[0],
                                     feature_sizes[1],
                                     features[1],
                                     feature_sizes[2],
                                     features[2],
                                     feature_sizes[3],
                                     features[3],
                                     template_size_inout,
                                     template_out);
  if (*template_size_inout > capacity ||
      *template_size_inout > CV2_BCM5880_TEMPLATE_CAPACITY)
    {
      secure_clear (template_out, capacity);
      *template_size_inout = 0;
      return CV2_BCM5880_NATIVE_INVALID_PARAMETER;
    }
  return status;
}

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
  uint32_t *result_out)
{
  uint32_t capacity;
  uint32_t status;

  if (adapter == NULL || !adapter->initialized ||
      adapter->commit_enrollment == NULL || token == NULL ||
      output_size_inout == NULL ||
      (input0_size != 0 && input0 == NULL) ||
      (input1_size != 0 && input1 == NULL) ||
      input1_size > 0x1064u)
    return CV2_BCM5880_NATIVE_INVALID_PARAMETER;

  capacity = *output_size_inout;
  if ((capacity != 0 &&
       (output == NULL || capacity > CV2_BCM5880_NATIVE_COMMIT_MAX_OUTPUT)) ||
      (capacity == 0 && result_out == NULL))
    return CV2_BCM5880_NATIVE_INVALID_PARAMETER;

  status = adapter->commit_enrollment (handle,
                                        token,
                                        input0_size,
                                        input0,
                                        input1_size,
                                        input1,
                                        output_size_inout,
                                        output,
                                        result_out);
  if (*output_size_inout > capacity ||
      *output_size_inout > CV2_BCM5880_NATIVE_COMMIT_MAX_OUTPUT)
    {
      if (output != NULL && capacity != 0)
        secure_clear (output, capacity);
      *output_size_inout = 0;
      return CV2_BCM5880_NATIVE_INVALID_PARAMETER;
    }
  return status;
}

const char *
cv2_bcm5880_abi_error_name (Cv2Bcm5880AbiError error)
{
  switch (error)
    {
    case CV2_BCM5880_ABI_ERROR_NONE:
      return "none";
    case CV2_BCM5880_ABI_ERROR_INVALID_ARGUMENT:
      return "invalid-argument";
    case CV2_BCM5880_ABI_ERROR_MOCK_MODE_REQUIRED:
      return "mock-mode-required";
    }
  return "unknown";
}
