#include "filter1.h"

int bar = 26;
int baz = 28;

struct A foo1 = { 1, &bar, &baz };
static struct A pfoo1 = { 1, &bar, &baz };
struct A *pfoo1p = &pfoo1;

int f1 (void)
{
  return bar + baz;
}
