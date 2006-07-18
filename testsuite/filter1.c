#include "filter1.h"
#include <stdlib.h>

int main()
{
  if (f1 () != 54 || f2 () != 54 || f3 () != 54)
    abort ();
  if (foo1.a != 1 || *foo1.b != 24 || *foo1.c != 30)
    abort ();
  if (foo2.a != 2 || *foo2.b != 24 || *foo2.c != 30)
    abort ();
  if (pfoo1p->a != 1 || *pfoo1p->b != 24 || *pfoo1p->c != 30)
    abort ();
  if (pfoo2p->a != 2 || *pfoo2p->b != 24 || *pfoo2p->c != 30)
    abort ();
  exit (0);
}
