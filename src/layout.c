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

#define DEBUG_LAYOUT

#ifdef DEBUG_LAYOUT
static void
print_ent (struct prelink_entry *e)
{
  printf ("%s: %08x %08x\n", e->filename, (int)e->base, (int)e->end);
}

static void
print_list (struct prelink_entry *e)
{
  for (; e; e = e->next)
    print_ent (e);
  printf ("\n");
}
#endif

struct layout_libs
  {
    struct prelink_entry **libs;
    int nlibs;
    struct prelink_entry **binlibs;
    int nbinlibs;
  };

static int
find_libs (void **p, void *info)
{
  struct layout_libs *l = (struct layout_libs *) info;
  struct prelink_entry *e = * (struct prelink_entry **) p;

  if (e->type == ET_DYN || e->type == ET_EXEC
      || e->type == ET_CACHE_DYN || e->type == ET_CACHE_EXEC)
    l->binlibs[l->nbinlibs++] = e;
  if (e->type == ET_DYN || e->type == ET_CACHE_DYN)
    l->libs[l->nlibs++] = e;
  if (force)
    e->done = 0;
  if (e->type == ET_CACHE_DYN || e->type == ET_CACHE_EXEC)
    e->done = 2;

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
  if (a->refs)
    {
      i = strcmp (a->soname, b->soname);
      if (i)
	return i;
    }
  return strcmp (a->filename, b->filename);
}

static int
addr_cmp (const void *A, const void *B)
{
  struct prelink_entry *a = * (struct prelink_entry **) A;
  struct prelink_entry *b = * (struct prelink_entry **) B;

  if (! a->done)
    return b->done ? 1 : 0;
  else if (! b->done)
    return -1;
  if (a->base < b->base)
    return -1;
  else if (a->base > b->base)
    return 1;
  if (a->end < b->end)
    return -1;
  else if (a->end > b->end)
    return 1;
  return 0;
}

int
layout_libs (void)
{
  struct layout_libs l;
  int i, j, k, m, done;
  int class;
  GElf_Addr mmap_start, mmap_base, mmap_end, mmap_fin, page_size;
  GElf_Addr base, size;
  DSO *dso;
  struct prelink_entry *list = NULL, *e;

  l.libs =
    (struct prelink_entry **) alloca (prelink_entry_count
				      * sizeof (struct prelink_entry *));
  l.nlibs = 0;
  l.binlibs =
    (struct prelink_entry **) alloca (prelink_entry_count
				      * sizeof (struct prelink_entry *));
  l.nbinlibs = 0;
  htab_traverse (prelink_filename_htab, find_libs, &l);

  dso = open_dso (dynamic_linker);
  if (dso == NULL)
    error (EXIT_FAILURE, 0, "Could not assign base addresses to libraries");
  mmap_base = dso->arch->mmap_base;
  mmap_end = dso->arch->mmap_end;
  /* The code below relies on having a VA slot as big as <mmap_base,mmap_end)
     above mmap_end for -R.  */
  if (mmap_end + (mmap_end - mmap_base) <= mmap_end)
    random_base = 0;
  page_size = dso->arch->page_size;
  class = dso->arch->class;
  close_dso (dso);

  /* Make sure there is some room between libraries.  */
  for (i = 0; i < l.nlibs; ++i)
    if (l.libs[i]->type == ET_DYN)
      l.libs[i]->end = (l.libs[i]->end + 8 * page_size) & ~(page_size - 1);

  /* Put the already prelinked libs into double linked list.  */
  qsort (l.libs, l.nlibs, sizeof (struct prelink_entry *), addr_cmp);
  for (i = 0; i < l.nlibs; ++i)
    if (! l.libs[i]->done || l.libs[i]->end >= mmap_base)
      break;
  j = 0;
  if (i < l.nlibs && l.libs[i]->done)
    {
      if (l.libs[i]->base < mmap_base)
	random_base = 0;
      for (j = i + 1; j < l.nlibs; ++j)
	{
	  if (! l.libs[j]->done || l.libs[j]->base >= mmap_end)
	    break;

	  if (l.libs[j]->base < mmap_base || l.libs[j]->end > mmap_end)
	    random_base = 0;
	  l.libs[j]->prev = l.libs[j - 1];
	  l.libs[j - 1]->next = l.libs[j];
	}
      list = l.libs[i];
      list->prev = l.libs[j - 1];
      while (j < l.nlibs && l.libs[j]->done) ++j;
    }

  if (verbose && l.nlibs > j)
    printf ("Laying out %d libraries in virtual address space %0*llx-%0*llx\n",
	    l.nlibs - j, class == ELFCLASS32 ? 8 : 16, (long long) mmap_base,
	    class == ELFCLASS32 ? 8 : 16, (long long) mmap_end);

  qsort (l.libs, l.nlibs, sizeof (struct prelink_entry *), refs_cmp);
  mmap_start = 0;
  mmap_fin = mmap_end;
  done = 1;
  if (random_base)
    {
      int fd = open ("/dev/urandom", O_RDONLY);

      if (fd != -1)
	{
	  GElf_Addr x;

	  if (read (fd, &x, sizeof (x)) == sizeof (x))
	    {
	      mmap_start = x % (mmap_end - mmap_base);
	      mmap_start += mmap_base;
	    }

	  close (fd);
	}

      if (! mmap_start)
	{
	  mmap_start = ((mmap_end - mmap_base) >> 16)
		       * (time (NULL) & 0xffff);
	  mmap_start += mmap_base;
	}

      mmap_start = (mmap_start + page_size - 1) & ~(page_size - 1);
      if (list)
	{
	  for (e = list; e != NULL; e = e->next)
	    {
	      if (e->base >= mmap_start)
		break;
	      if (e->end > mmap_start)
		mmap_start = (e->end + page_size - 1) & ~(page_size - 1);
	      e->base += mmap_end - mmap_base;
	      e->end += mmap_end - mmap_base;
	      e->done |= 0x80;
	    }

	  if (mmap_start < mmap_end)
	    {
	      if (e && e != list)
		{
		  list->prev->next = list;
		  list = e;
		  list->prev->next = NULL;
		  list->prev = NULL;
		}
	      done |= 0x80;
	      mmap_fin = mmap_end + (mmap_start - mmap_base);
	    }
	  else
	    {
	      mmap_start = mmap_base;
	      for (e = list; e != NULL; e = e->next)
		if (e->done & 0x80)
		  {
		    e->done &= ~0x80;
		    e->base -= mmap_end - mmap_base;
		    e->end -= mmap_end - mmap_base;
		  }
	    }
	}
    }
  else
    mmap_start = mmap_base;

  mmap_start = (mmap_start + page_size - 1) & ~(page_size - 1);

  for (i = 0; i < l.nlibs; ++i)
    l.libs[i]->u.tmp = -1;
  m = -1;

  for (i = 0; i < l.nlibs; ++i)
    if (! l.libs[i]->done)
      {
	if (conserve_memory)
	  {
	    /* If conserving virtual address space, only consider libraries
	       which ever appear together with this one.  Otherwise consider
	       all libraries.  */
	    m = i;
	    for (j = 0; j < l.nbinlibs; ++j)
	      {
		for (k = 0; k < l.binlibs[j]->ndepends; ++k)
		  if (l.binlibs[j]->depends[k] == l.libs[i])
		    {
		      for (k = 0; k < l.binlibs[j]->ndepends; ++k)
			l.binlibs[j]->depends[k]->u.tmp = m;
		      break;
		    }
	      }
	  }

	size = l.libs[i]->end - l.libs[i]->base;
	base = mmap_start;
	for (e = list; e; e = e->next)
	  if (e->u.tmp == m)
	    {
	      if (base < mmap_end && base + size > mmap_end)
		base = mmap_end;

	      if (base + size <= e->base)
		goto found;

	      if (base < e->end)
		base = e->end;
	    }

	if (base + size > mmap_fin)
	  goto not_found;
found:
	l.libs[i]->base = base;
	l.libs[i]->end = base + size;
	if (base >= mmap_end)
	  l.libs[i]->done = done;
	else
	  l.libs[i]->done = 1;
	if (list == NULL)
	  {
	    list = l.libs[i];
	    list->prev = list;
	  }
	else
	  {
	    if (e == NULL)
	      e = list->prev;
	    else
	      e = e->prev;
	    while (e != list && e->base > base)
	      e = e->prev;
	    if (e->base > base)
	      {
		l.libs[i]->next = list;
		l.libs[i]->prev = list->prev;
		list->prev = l.libs[i];
		list = l.libs[i];
	      }
	    else
	      {
		l.libs[i]->next = e->next;
		l.libs[i]->prev = e;
		if (e->next)
		  e->next->prev = l.libs[i];
		else
		  list->prev = l.libs[i];
		e->next = l.libs[i];
	      }
	  }
#ifdef DEBUG_LAYOUT
	{
	  struct prelink_entry *last = list;
	  base = 0;
	  for (e = list; e; last = e, e = e->next)
	    {
	      if (e->base < base)
		abort ();
	      base = e->base;
	      if ((e == list && e->prev->next != NULL)
		  || (e != list && e->prev->next != e))
		abort ();
	    }
	  if (list->prev != last)
	    abort ();
	}
#endif
	continue;

not_found:
	error (EXIT_FAILURE, 0, "Could not find virtual address slot for %s",
	       l.libs[i]->filename);
      }

  if (done & 0x80)
    for (e = list; e != NULL; e = e->next)
      if (e->done & 0x80)
	{
	  e->done &= ~0x80;
	  e->base -= mmap_end - mmap_base;
	  e->end -= mmap_end - mmap_base;
	}

  if (verbose)
    {
      printf ("Assigned virtual address space slots for libraries:\n");
      for (i = 0; i < l.nlibs; ++i)
	if (l.libs[i]->done >= 1)
	  printf ("%-60s %0*llx-%0*llx\n", l.libs[i]->filename,
		  class == ELFCLASS32 ? 8 : 16, (long long) l.libs[i]->base,
		  class == ELFCLASS32 ? 8 : 16, (long long) l.libs[i]->end);
    }

#ifdef DEBUG_LAYOUT
  {
    struct prelink_entry **deps =
      (struct prelink_entry **) alloca (l.nlibs
					* sizeof (struct prelink_entry *));
    int deps_cmp (const void *A, const void *B)
      {
	struct prelink_entry *a = * (struct prelink_entry **) A;
	struct prelink_entry *b = * (struct prelink_entry **) B;

	if (a->base < b->base)
	  return -1;
	if (a->base > b->base)
	  return 1;
	return 0;
      }

    for (i = 0; i < l.nbinlibs; ++i)
      {
	for (j = 0; j < l.binlibs[i]->ndepends; ++j)
	  if ((l.binlibs[i]->depends[j]->type != ET_DYN
	       && l.binlibs[i]->depends[j]->type != ET_CACHE_DYN)
	      || l.binlibs[i]->depends[j]->done == 0)
	  break;
	if (j < l.binlibs[i]->ndepends)
	  continue;
	memcpy (deps, l.binlibs[i]->depends,
		l.binlibs[i]->ndepends * sizeof (struct prelink_entry *));
	qsort (deps, l.binlibs[i]->ndepends, sizeof (struct prelink_entry *),
	       deps_cmp);
	for (j = 1; j < l.binlibs[i]->ndepends; ++j)
	  if (deps[j]->base < deps[j - 1]->end
	      && (deps[j]->type == ET_DYN || deps[j - 1]->type == ET_DYN))
	    abort ();
      }
  }
#endif

  return 0;
}
