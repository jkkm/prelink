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
#include <fcntl.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include "prelinktab.h"

struct collect_libs
  {
    struct prelink_entry **libs;
    int nlibs;
  };

static int
find_libs (void **p, void *info)
{
  struct collect_libs *l = (struct collect_libs *) info;
  struct prelink_entry *e = * (struct prelink_entry **) p;

  if (e->type == ET_DYN && e->done == 1)
    l->libs[l->nlibs++] = e;

  return 1;
}

int
prelink_libs (void)
{
  struct collect_libs l;

  l.libs =
    (struct prelink_entry **) alloca (prelink_entry_count
				      * sizeof (struct prelink_entry *));
  l.nlibs = 0;
  htab_traverse (prelink_filename_htab, find_libs, &l);

  for (i = 
  return 0;
}
