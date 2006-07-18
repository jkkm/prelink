/* Copyright (C) 2001 Red Hat, Inc.
   Written by Jakub Jelinek <jakub@redhat.com>, 2001.

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2, or (at your option)
   any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software Foundation,
   Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.  */

#include <alloca.h>
#include <errno.h>
#include <error.h>
#include <string.h>
#include "prelinktab.h"

struct layout_libs
  {
    struct prelink_entry **libs;
    int nlibs;
  };

static int
find_libs (void **p, void *info)
{
  struct layout_libs *l = (struct layout_libs *) info;
  struct prelink_entry *e = * (struct prelink_entry **) p;

  if (e->type == ET_DYN)
    l->libs[l->nlibs++] = e;

  return 1;
}

static int
refs_cmp (const void *A, const void *B)
{
  struct prelink_entry *a = * (struct prelink_entry **) A;
  struct prelink_entry *b = * (struct prelink_entry **) B;
  int i;

  /* Dynamic linkers first.  */
  if (! a->ndepends && b->ndepends)
    return -1;
  if (a->ndepends && ! b->ndepends)
    return 1;
  /* Most widely used libraries first.  */
  if (a->refs > b->refs)
    return -1;
  if (a->refs < b->refs)
    return 1;
  /* Largest libraries first.  */
  if (a->end - a->base > b->end - b->base)
    return -1;
  if (a->end - a->base < b->end - b->base)
    return 1;
  i = strcmp (a->soname, b->soname);
  if (i)
    return i;
  return strcmp (a->filename, b->filename);
}

int
layout_libs (void)
{
  struct layout_libs l;
  int i;

  l.libs =
    (struct prelink_entry **) alloca (prelink_entry_count
				      * sizeof (struct prelink_entry *));
  l.nlibs = 0;
  htab_traverse (prelink_filename_htab, find_libs, &l);
  qsort (l.libs, l.nlibs, sizeof (struct prelink_entry *), refs_cmp);
  for (i = 0; i < l.nlibs; ++i)
    printf ("%s %d %08x %08x %d\n", l.libs[i]->filename, l.libs[i]->refs, (int) l.libs[i]->base, (int) l.libs[i]->end, l.libs[i]->done);
}
