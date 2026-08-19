#ifndef CV2_BCM5880_ENROLLMENT_COORDINATOR_H
#define CV2_BCM5880_ENROLLMENT_COORDINATOR_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define CV2_BCM5880_ENROLLMENT_ID_SIZE 20u
#define CV2_BCM5880_BUFFERED_FEATURES 3u
#define CV2_BCM5880_TEMPLATE_FEATURES 4u
#define CV2_BCM5880_FEATURE_CAPACITY 0x258u
#define CV2_BCM5880_TEMPLATE_CAPACITY 0x708u
#define CV2_BCM5880_TOKEN_RANDOM_PREFIX_SIZE 4u

/*
 * Mock-only host coordinator reconstructed from the Windows A21 selected
 * BCM5880 path. It intentionally exposes no commit operation and has no
 * driver-symbol resolver. The implementation additionally requires the
 * CV2_BCM5880_COORDINATOR_MOCK_ONLY compile-time gate.
 */

typedef enum
{
  CV2_BCM5880_EXECUTION_DISABLED = 0,
  CV2_BCM5880_EXECUTION_MOCK_ONLY = 1,
} Cv2Bcm5880ExecutionMode;

typedef enum
{
  CV2_BCM5880_OUTCOME_REJECTED = 0,
  CV2_BCM5880_OUTCOME_ACCEPTED_MORE = 1,
  CV2_BCM5880_OUTCOME_TEMPLATE_READY_COMMIT_BLOCKED = 2,
} Cv2Bcm5880Outcome;

typedef enum
{
  CV2_BCM5880_ERROR_NONE = 0,
  CV2_BCM5880_ERROR_INVALID_ARGUMENT,
  CV2_BCM5880_ERROR_ALLOCATION,
  CV2_BCM5880_ERROR_MOCK_MODE_REQUIRED,
  CV2_BCM5880_ERROR_ID_MISMATCH,
  CV2_BCM5880_ERROR_FEATURE_SIZE,
  CV2_BCM5880_ERROR_TEMPLATE_STATUS,
  CV2_BCM5880_ERROR_TEMPLATE_SIZE,
  CV2_BCM5880_ERROR_TOKEN_RANDOM,
  CV2_BCM5880_ERROR_TERMINAL,
} Cv2Bcm5880Error;

typedef uint32_t (*Cv2Bcm5880CreateTemplateMock) (
  void *user_data,
  uint32_t handle,
  const uint32_t feature_sizes[CV2_BCM5880_TEMPLATE_FEATURES],
  const uint8_t *const features[CV2_BCM5880_TEMPLATE_FEATURES],
  uint32_t *template_size_inout,
  uint8_t *template_out);

typedef int (*Cv2Bcm5880RandomBytesMock) (void *user_data,
                                          uint8_t *output,
                                          size_t size);

typedef struct
{
  Cv2Bcm5880CreateTemplateMock create_template;
  Cv2Bcm5880RandomBytesMock random_bytes;
  void *user_data;
} Cv2Bcm5880MockOperations;

typedef struct
{
  Cv2Bcm5880ExecutionMode mode;
  uint32_t handle;
  const uint8_t *enrollment_id;
  Cv2Bcm5880MockOperations operations;
} Cv2Bcm5880MockConfig;

typedef struct
{
  unsigned int buffered_features;
  bool template_ready;
  uint32_t template_size;
  bool commit_permitted;
  bool terminal;
  Cv2Bcm5880Error last_error;
  uint32_t last_native_status;
} Cv2Bcm5880Snapshot;

typedef struct Cv2Bcm5880MockCoordinator Cv2Bcm5880MockCoordinator;

Cv2Bcm5880MockCoordinator *
cv2_bcm5880_mock_coordinator_new (const Cv2Bcm5880MockConfig *config,
                                  Cv2Bcm5880Error *error_out);

void
cv2_bcm5880_mock_coordinator_free (Cv2Bcm5880MockCoordinator *coordinator);

Cv2Bcm5880Outcome
cv2_bcm5880_mock_coordinator_accept_feature (
  Cv2Bcm5880MockCoordinator *coordinator,
  const uint8_t enrollment_id[CV2_BCM5880_ENROLLMENT_ID_SIZE],
  const void *feature,
  uint32_t feature_size);

Cv2Bcm5880Snapshot
cv2_bcm5880_mock_coordinator_snapshot (
  const Cv2Bcm5880MockCoordinator *coordinator);

const char *
cv2_bcm5880_error_name (Cv2Bcm5880Error error);

#endif
