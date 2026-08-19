#include <stdint.h>
#include <stdio.h>

uint32_t
cv_cmd_enrollment_started (void)
{
  fprintf (stderr, "[wrong-owner] unexpected 0x8A dependency called\n");
  return 0;
}
