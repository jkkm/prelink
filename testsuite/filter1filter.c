#include "filter1.h"

int bar = 24;
int baz = 22;

struct A foo2 = { 2, &bar, &baz };
static struct A pfoo2 = { 2, &bar, &baz };
struct A *pfoo2p = &pfoo2;

int f2 (void)
{
  return bar + baz;
}
