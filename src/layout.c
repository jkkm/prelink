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
  struct prelink_entry *f;

  if (! e)
    return;
  print_ent (e);
  for (f = e->next; f != e; f = f->next)
    print_ent (f);
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
  int i, j, k, m;
  int class;
  GElf_Addr mmap_start, mmap_base, mmap_end, page_size;
  GElf_Addr base, size;
  DSO *dso;
  struct prelink_entry *list = NULL, *low = NULL, *e;

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
      for (j = i + 1; j < l.nlibs; ++j)
	{
	  if (! l.libs[j]->done || l.libs[j]->base >= mmap_end)
	    break;

	  l.libs[j]->prev = l.libs[j - 1];
	  l.libs[j - 1]->next = l.libs[j];
	}
      list = l.libs[i];
      list->prev = l.libs[j - 1];
      l.libs[j - 1]->next = list;
      while (j < l.nlibs && l.libs[j]->done) ++j;
    }

  if (verbose && l.nlibs > j)
    printf ("Laying out %d libraries in virtual address space %0*llx-%0*llx\n",
	    l.nlibs - j, class == ELFCLASS32 ? 8 : 16, (long long) mmap_base,
	    class == ELFCLASS32 ? 8 : 16, (long long) mmap_end);

  qsort (l.libs, l.nlibs, sizeof (struct prelink_entry *), refs_cmp);
  mmap_start = 0;
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

      if (! mmap_base)
	{
	  mmap_start = ((mmap_end - mmap_base) >> 16)
		       * (time (NULL) & 0xffff);
	  mmap_start += mmap_base;
	}
    }
  else
    mmap_start = mmap_base;

  mmap_start = (mmap_start + page_size - 1) & ~(page_size - 1);

  if (list)
    {
      low = list;
      e = list;
      do
	{
	  if (e->end > mmap_start)
	    {
	      list = e;
	      break;
	    }
	} while ((e = e->next) != list);
    }

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
	j = 0;
	if ((e = list) != NULL)
	  do
	    {
	      if (e->u.tmp == m)
		{
		  if (e->end < mmap_start && ! j)
		    {
		      j = 1;
		      if (base + size < mmap_end)
			goto found;
		      base = mmap_base;
		      if (base == mmap_start)
			goto not_found;
		    }

		  if (base + size <= e->base)
		    goto found;

		  if (base < mmap_start && e->end >= mmap_start)
		    goto not_found;

		  if (base < e->end)
		    base = e->end;
		}
	    } while ((e = e->next) != list);

	if (base + size >= mmap_end)
	  {
	    base = mmap_base;
	    j = 1;
	    if (base == mmap_start)
	      goto not_found;
	  }
	if (j && base <= mmap_start)
	  {
	    if (base + size > mmap_start)
	      goto not_found;

	    if (list && list->u.tmp == m && base + size > list->base)
	      goto not_found;
	  }

found:
	l.libs[i]->base = base;
	l.libs[i]->end = base + size;
	l.libs[i]->done = 1;
	if (e)
	  {
	    struct prelink_entry *f;

	    if (e->base > base)
	      {
		for (f = e->prev; f != low->prev; f = f->prev)
		  if (f->base <= base)
		    break;
	      }
	    else
	      {
		for (f = e->next; f != low; f = f->next)
		  if (f->base >= base)
		    break;
		f = f->prev;
	      }
	    e = f;
	    if (f->base == base && f->end > base + size)
	      {
		for (e = f->prev; e != f; e = e->prev)
		  if (e->base != base || e->end <= base + size)
		    break;
	      }
	    else if (f->next->base == base && f->next->end < base + size)
	      {
		for (e = f->next; e != f; e = e->next)
		  if (e->base != base || e->end >= base + size)
		    break;
		e = e->prev;
	      }
	    f = l.libs[i];
	    f->next = e->next;
	    e->next->prev = f;
	    e->next = f;
	    f->prev = e;

	    /* Adjust list pointer if necessary.  */
	    if (f->end <= list->end && f->end > mmap_start)
	      {
		for (list = f->prev; list != f; list = list->prev)
		  if (list->end > f->end || list->end <= mmap_start)
		    break;
		list = list->next;
	      }

	    /* Adjust low pointer if necessary.  */
	    if (f->base <= low->base)
	      {
		if (f->base < low->base)
		  low = f;
		else
		  {
		    for (low = f->prev; low != f; low = low->prev)
		      if (low->base != f->base)
			break;
		    low = low->next;
		  }
	      }
	  }
	else
	  {
	    list = l.libs[i];
	    list->prev = list;
	    list->next = list;
	    low = list;
	  }

#ifdef DEBUG_LAYOUT
	for (e = list->next, k = 0; e != list; e = e->next)
	  {
	    if (e->base < e->prev->base)
	      {
	        if (k)
	          {
	            printf ("internal error #1 %d\n", i);
	            print_ent (l.libs[i]);
	            printf ("\n");
	            print_list (list);
	            fflush (NULL);
	            abort ();
	          }
	        k = 1;
	        continue;
	      }
	    if (k && e->base > list->base)
	      {
		printf ("internal error #2 %d\n", i);
		print_ent (l.libs[i]);
		printf ("\n");
		print_list (list);
		fflush (NULL);
		abort ();
	      }
	    if (e->base == e->prev->base && e->end < e->prev->end)
	      {
		printf ("internal error #3 %d\n", i);
		print_ent (l.libs[i]);
		printf ("\n");
		print_list (list);
		fflush (NULL);
		abort ();
	      }
	  }
	if (list->end > mmap_start && list->prev->end > mmap_start
	    && list->prev->base < list->base)
	  {
	    printf ("internal error #4 %d\n", i);
	    print_ent (l.libs[i]);
	    printf ("\n");
	    print_list (list);
	    fflush (NULL);
	    abort ();
	  }
	if (low->base > low->prev->base
	    || (low->base == low->prev->base && low->end > low->prev->end))
	  {
	    printf ("internal error #5 %d\n", i);
	    print_ent (l.libs[i]);
	    printf ("\n");
	    print_list (list);
	    fflush (NULL);
	    abort ();
	  }
#endif

	continue;

not_found:
	error (EXIT_FAILURE, 0, "Could not find virtual address slot for %s",
	       l.libs[i]->filename);
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
