struct A
  {
    char a;
    int *b;
    int *c;
  };

extern struct A foo1, foo2;
extern struct A *pfoo1p, *pfoo2p;
extern int bar, baz;

extern int f1 (void), f2 (void), f3 (void);
