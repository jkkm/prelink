#include <stdlib.h>

extern int dummy;

int main (void)
{
  if (dummy != 24)
    abort ();
  exit (0);
}
