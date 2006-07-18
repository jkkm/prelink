extern int f1 (int dummy);

int f2 (int add)
{
  if (add)
    return f1 (0) + 26;
  return f1 (0);
}
