#include "reloc1.h"
#include <stdlib.h>

int main()
{
  if (foo.a != 1 || foo.b != &foo || foo.c != &bar || bar != 26)
    abort ();
  if (f1 () != 11 || f2 () != 12)
    abort ();
  exit (0);
}
