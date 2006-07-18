#include <stdlib.h>

extern int f2 (int add);

int main()
{
  if (f2 (1) != 27 || f2 (0) != 1)
    abort ();
  exit (0);
}
