#include "bcm5880_enrollment_coordinator.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct
{
  const char *scenario;
  unsigned int template_calls;
  unsigned int random_calls;
} MockState;

static uint32_t
mock_create_template (
  void *user_data,
  uint32_t handle,
  const uint32_t feature_sizes[CV2_BCM5880_TEMPLATE_FEATURES],
  const uint8_t *const features[CV2_BCM5880_TEMPLATE_FEATURES],
  uint32_t *template_size_inout,
  uint8_t *template_out)
{
  MockState *state = user_data;

  state->template_calls++;
  if (handle != 7 || *template_size_inout != CV2_BCM5880_TEMPLATE_CAPACITY)
    abort ();
  for (unsigned int index = 0; index < CV2_BCM5880_TEMPLATE_FEATURES;
       index++)
    if (feature_sizes[index] != 100u + index || features[index] == NULL ||
        features[index][0] != (uint8_t) (0x10u + index))
      abort ();

  if (strcmp (state->scenario, "template-error") == 0)
    return 0x59;
  if (strcmp (state->scenario, "template-oversize") == 0)
    {
      *template_size_inout = CV2_BCM5880_TEMPLATE_CAPACITY + 1;
      return 0;
    }
  memset (template_out, 0xa5, 64);
  *template_size_inout = 64;
  return 0;
}

static int
mock_random_bytes (void *user_data, uint8_t *output, size_t size)
{
  MockState *state = user_data;

  state->random_calls++;
  if (size != CV2_BCM5880_TOKEN_RANDOM_PREFIX_SIZE)
    abort ();
  if (strcmp (state->scenario, "random-error") == 0)
    return -1;
  memset (output, 0x5a, size);
  return 0;
}

static void
print_snapshot (const char *label,
                const Cv2Bcm5880MockCoordinator *coordinator,
                const MockState *state)
{
  Cv2Bcm5880Snapshot snapshot =
    cv2_bcm5880_mock_coordinator_snapshot (coordinator);

  printf ("%s buffered=%u ready=%u template_size=%u commit_permitted=%u "
          "terminal=%u error=%s native=0x%x template_calls=%u random_calls=%u\n",
          label,
          snapshot.buffered_features,
          snapshot.template_ready ? 1u : 0u,
          snapshot.template_size,
          snapshot.commit_permitted ? 1u : 0u,
          snapshot.terminal ? 1u : 0u,
          cv2_bcm5880_error_name (snapshot.last_error),
          snapshot.last_native_status,
          state->template_calls,
          state->random_calls);
}

int
main (int argc, char **argv)
{
  uint8_t enrollment_id[CV2_BCM5880_ENROLLMENT_ID_SIZE];
  uint8_t wrong_id[CV2_BCM5880_ENROLLMENT_ID_SIZE];
  uint8_t feature[CV2_BCM5880_FEATURE_CAPACITY];
  MockState state;
  Cv2Bcm5880MockConfig config;
  Cv2Bcm5880MockCoordinator *coordinator;
  Cv2Bcm5880Error error;
  Cv2Bcm5880Outcome outcome = CV2_BCM5880_OUTCOME_REJECTED;

  if (argc != 2)
    return 64;
  memset (&state, 0, sizeof state);
  state.scenario = argv[1];
  memset (enrollment_id, 0x31, sizeof enrollment_id);
  memset (wrong_id, 0x32, sizeof wrong_id);
  memset (&config, 0, sizeof config);
  config.mode = strcmp (state.scenario, "disabled") == 0
                  ? CV2_BCM5880_EXECUTION_DISABLED
                  : CV2_BCM5880_EXECUTION_MOCK_ONLY;
  config.handle = 7;
  config.enrollment_id = enrollment_id;
  config.operations.create_template = mock_create_template;
  config.operations.random_bytes = mock_random_bytes;
  config.operations.user_data = &state;
  if (strcmp (state.scenario, "missing-operations") == 0)
    config.operations.create_template = NULL;

  coordinator = cv2_bcm5880_mock_coordinator_new (&config, &error);
  if (coordinator == NULL)
    {
      printf ("init=failed error=%s template_calls=%u random_calls=%u\n",
              cv2_bcm5880_error_name (error),
              state.template_calls,
              state.random_calls);
      return 0;
    }

  if (strcmp (state.scenario, "id-mismatch") == 0)
    {
      memset (feature, 0x10, sizeof feature);
      outcome = cv2_bcm5880_mock_coordinator_accept_feature (
        coordinator, wrong_id, feature, 100);
      printf ("mismatch_outcome=%u\n", (unsigned int) outcome);
      print_snapshot ("after-mismatch", coordinator, &state);
    }
  else if (strcmp (state.scenario, "oversize") == 0)
    {
      outcome = cv2_bcm5880_mock_coordinator_accept_feature (
        coordinator,
        enrollment_id,
        feature,
        CV2_BCM5880_FEATURE_CAPACITY + 1);
      printf ("oversize_outcome=%u\n", (unsigned int) outcome);
      print_snapshot ("after-oversize", coordinator, &state);
      cv2_bcm5880_mock_coordinator_free (coordinator);
      return 0;
    }

  for (unsigned int index = 0; index < CV2_BCM5880_TEMPLATE_FEATURES;
       index++)
    {
      memset (feature, (int) (0x10u + index), sizeof feature);
      outcome = cv2_bcm5880_mock_coordinator_accept_feature (
        coordinator, enrollment_id, feature, 100u + index);
      printf ("feature=%u outcome=%u\n", index + 1, (unsigned int) outcome);
      if (strcmp (state.scenario, "three-only") == 0 && index == 2)
        break;
    }
  print_snapshot ("final", coordinator, &state);

  if (strcmp (state.scenario, "happy") == 0)
    {
      memset (feature, 0x14, sizeof feature);
      outcome = cv2_bcm5880_mock_coordinator_accept_feature (
        coordinator, enrollment_id, feature, 104);
      printf ("post-ready-outcome=%u\n", (unsigned int) outcome);
      print_snapshot ("post-ready", coordinator, &state);
    }

  cv2_bcm5880_mock_coordinator_free (coordinator);
  return 0;
}
