#ifndef CV2_BCM5880_COORDINATOR_MOCK_ONLY
#error "BCM5880 coordinator is mock-only; define CV2_BCM5880_COORDINATOR_MOCK_ONLY"
#endif

#include "bcm5880_enrollment_coordinator.h"

#include <stdlib.h>
#include <string.h>

struct Cv2Bcm5880MockCoordinator
{
  uint32_t handle;
  uint8_t enrollment_id[CV2_BCM5880_ENROLLMENT_ID_SIZE];
  Cv2Bcm5880MockOperations operations;
  unsigned int buffered_features;
  uint32_t feature_sizes[CV2_BCM5880_BUFFERED_FEATURES];
  uint8_t features[CV2_BCM5880_BUFFERED_FEATURES]
                  [CV2_BCM5880_FEATURE_CAPACITY];
  uint32_t template_size;
  uint8_t template_data[CV2_BCM5880_TEMPLATE_CAPACITY];
  uint8_t commit_token[CV2_BCM5880_ENROLLMENT_ID_SIZE];
  bool template_ready;
  bool terminal;
  Cv2Bcm5880Error last_error;
  uint32_t last_native_status;
};

static void
secure_clear (void *memory, size_t size)
{
  volatile uint8_t *bytes = memory;

  while (size-- > 0)
    *bytes++ = 0;
}

static Cv2Bcm5880Outcome
reject (Cv2Bcm5880MockCoordinator *coordinator,
        Cv2Bcm5880Error error,
        bool terminal)
{
  if (coordinator != NULL)
    {
      coordinator->last_error = error;
      if (terminal && !coordinator->terminal)
        {
          secure_clear (coordinator->enrollment_id,
                        sizeof coordinator->enrollment_id);
          secure_clear (coordinator->feature_sizes,
                        sizeof coordinator->feature_sizes);
          secure_clear (coordinator->features,
                        sizeof coordinator->features);
          secure_clear (coordinator->template_data,
                        sizeof coordinator->template_data);
          secure_clear (coordinator->commit_token,
                        sizeof coordinator->commit_token);
          coordinator->buffered_features = 0;
          coordinator->template_size = 0;
          coordinator->template_ready = false;
          coordinator->terminal = true;
        }
    }
  return CV2_BCM5880_OUTCOME_REJECTED;
}

Cv2Bcm5880MockCoordinator *
cv2_bcm5880_mock_coordinator_new (const Cv2Bcm5880MockConfig *config,
                                  Cv2Bcm5880Error *error_out)
{
  Cv2Bcm5880MockCoordinator *coordinator;
  Cv2Bcm5880Error error = CV2_BCM5880_ERROR_NONE;

  if (config == NULL || config->enrollment_id == NULL ||
      config->operations.create_template == NULL ||
      config->operations.random_bytes == NULL)
    error = CV2_BCM5880_ERROR_INVALID_ARGUMENT;
  else if (config->mode != CV2_BCM5880_EXECUTION_MOCK_ONLY)
    error = CV2_BCM5880_ERROR_MOCK_MODE_REQUIRED;

  if (error != CV2_BCM5880_ERROR_NONE)
    {
      if (error_out != NULL)
        *error_out = error;
      return NULL;
    }

  coordinator = calloc (1, sizeof *coordinator);
  if (coordinator == NULL)
    {
      if (error_out != NULL)
        *error_out = CV2_BCM5880_ERROR_ALLOCATION;
      return NULL;
    }

  coordinator->handle = config->handle;
  memcpy (coordinator->enrollment_id,
          config->enrollment_id,
          sizeof coordinator->enrollment_id);
  coordinator->operations = config->operations;
  if (error_out != NULL)
    *error_out = CV2_BCM5880_ERROR_NONE;
  return coordinator;
}

void
cv2_bcm5880_mock_coordinator_free (Cv2Bcm5880MockCoordinator *coordinator)
{
  if (coordinator == NULL)
    return;
  secure_clear (coordinator, sizeof *coordinator);
  free (coordinator);
}

Cv2Bcm5880Outcome
cv2_bcm5880_mock_coordinator_accept_feature (
  Cv2Bcm5880MockCoordinator *coordinator,
  const uint8_t enrollment_id[CV2_BCM5880_ENROLLMENT_ID_SIZE],
  const void *feature,
  uint32_t feature_size)
{
  const uint8_t *feature_bytes = feature;
  const uint8_t *feature_pointers[CV2_BCM5880_TEMPLATE_FEATURES];
  uint32_t feature_sizes[CV2_BCM5880_TEMPLATE_FEATURES];
  uint32_t status;

  if (coordinator == NULL || enrollment_id == NULL || feature == NULL)
    return reject (coordinator,
                   CV2_BCM5880_ERROR_INVALID_ARGUMENT,
                   true);
  if (coordinator->terminal)
    return reject (coordinator, CV2_BCM5880_ERROR_TERMINAL, true);
  if (memcmp (enrollment_id,
              coordinator->enrollment_id,
              CV2_BCM5880_ENROLLMENT_ID_SIZE) != 0)
    return reject (coordinator, CV2_BCM5880_ERROR_ID_MISMATCH, false);
  if (feature_size == 0 || feature_size > CV2_BCM5880_FEATURE_CAPACITY)
    return reject (coordinator, CV2_BCM5880_ERROR_FEATURE_SIZE, true);

  coordinator->last_error = CV2_BCM5880_ERROR_NONE;
  coordinator->last_native_status = 0;
  if (coordinator->buffered_features < CV2_BCM5880_BUFFERED_FEATURES)
    {
      unsigned int slot = coordinator->buffered_features;

      memcpy (coordinator->features[slot], feature_bytes, feature_size);
      coordinator->feature_sizes[slot] = feature_size;
      coordinator->buffered_features++;
      return CV2_BCM5880_OUTCOME_ACCEPTED_MORE;
    }

  for (unsigned int index = 0; index < CV2_BCM5880_BUFFERED_FEATURES;
       index++)
    {
      feature_sizes[index] = coordinator->feature_sizes[index];
      feature_pointers[index] = coordinator->features[index];
    }
  feature_sizes[CV2_BCM5880_BUFFERED_FEATURES] = feature_size;
  feature_pointers[CV2_BCM5880_BUFFERED_FEATURES] = feature_bytes;

  /* Windows resets the three-feature count before template creation. */
  coordinator->buffered_features = 0;
  coordinator->template_size = CV2_BCM5880_TEMPLATE_CAPACITY;
  status = coordinator->operations.create_template (
    coordinator->operations.user_data,
    coordinator->handle,
    feature_sizes,
    feature_pointers,
    &coordinator->template_size,
    coordinator->template_data);
  coordinator->last_native_status = status;
  if (status != 0)
    return reject (coordinator,
                   CV2_BCM5880_ERROR_TEMPLATE_STATUS,
                   true);
  if (coordinator->template_size == 0 ||
      coordinator->template_size > CV2_BCM5880_TEMPLATE_CAPACITY)
    return reject (coordinator,
                   CV2_BCM5880_ERROR_TEMPLATE_SIZE,
                   true);

  memset (coordinator->commit_token, 0, sizeof coordinator->commit_token);
  if (coordinator->operations.random_bytes (
        coordinator->operations.user_data,
        coordinator->commit_token,
        CV2_BCM5880_TOKEN_RANDOM_PREFIX_SIZE) != 0)
    return reject (coordinator,
                   CV2_BCM5880_ERROR_TOKEN_RANDOM,
                   true);

  coordinator->template_ready = true;
  coordinator->terminal = true;
  return CV2_BCM5880_OUTCOME_TEMPLATE_READY_COMMIT_BLOCKED;
}

Cv2Bcm5880Snapshot
cv2_bcm5880_mock_coordinator_snapshot (
  const Cv2Bcm5880MockCoordinator *coordinator)
{
  Cv2Bcm5880Snapshot snapshot = { 0 };

  if (coordinator == NULL)
    {
      snapshot.terminal = true;
      snapshot.last_error = CV2_BCM5880_ERROR_INVALID_ARGUMENT;
      return snapshot;
    }
  snapshot.buffered_features = coordinator->buffered_features;
  snapshot.template_ready = coordinator->template_ready;
  snapshot.template_size = coordinator->template_size;
  snapshot.commit_permitted = false;
  snapshot.terminal = coordinator->terminal;
  snapshot.last_error = coordinator->last_error;
  snapshot.last_native_status = coordinator->last_native_status;
  return snapshot;
}

const char *
cv2_bcm5880_error_name (Cv2Bcm5880Error error)
{
  switch (error)
    {
    case CV2_BCM5880_ERROR_NONE:
      return "none";
    case CV2_BCM5880_ERROR_INVALID_ARGUMENT:
      return "invalid-argument";
    case CV2_BCM5880_ERROR_ALLOCATION:
      return "allocation";
    case CV2_BCM5880_ERROR_MOCK_MODE_REQUIRED:
      return "mock-mode-required";
    case CV2_BCM5880_ERROR_ID_MISMATCH:
      return "id-mismatch";
    case CV2_BCM5880_ERROR_FEATURE_SIZE:
      return "feature-size";
    case CV2_BCM5880_ERROR_TEMPLATE_STATUS:
      return "template-status";
    case CV2_BCM5880_ERROR_TEMPLATE_SIZE:
      return "template-size";
    case CV2_BCM5880_ERROR_TOKEN_RANDOM:
      return "token-random";
    case CV2_BCM5880_ERROR_TERMINAL:
      return "terminal";
    }
  return "unknown";
}
