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

#include <assert.h>
#include <errno.h>
#include <error.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include "prelink.h"

const char *prelink_cache = "/etc/prelink.cache";

struct prelink_entry *prelinked;

int
prelink_load_cache (void)
{
  int fd, i, j, changed = 1;
  struct stat64 st;
  struct prelink_cache *cache;
  struct prelink_entry **depends, *ent;
  size_t cache_size;
  uint32_t string_start, *dep;

  fd = open (prelink_cache, O_RDONLY);
  if (fd < 0)
    return 0; /* The cache does not exist yet.  */

  if (fstat64 (fd, &st) < 0
      || st.st_size == 0)
    {
      close (fd);
      return 0;
    }

  cache = mmap (0, st.st_size, PROT_READ, MAP_SHARED, fd, 0);
  if (cache == MAP_FAILED)
    error (EXIT_FAILURE, errno, "mmap of prelink cache file failed.");
  cache_size = st.st_size;
  if (memcmp (cache->magic, PRELINK_CACHE_MAGIC,
	      sizeof (PRELINK_CACHE_MAGIC) - 1))
    error (EXIT_FAILURE, 0, "%s: is not prelink cache file",
	   prelink_cache);
  ent = (struct prelink_entry *)
	calloc (sizeof (struct prelink_entry) * cache->nlibs
		+ sizeof (struct prelink_entry *) * cache->ndeps, 1);
  if (ent == NULL)
    error (EXIT_FAILURE, ENOMEM, "Could not allocate memory for cache file");
  depends = (struct prelink_entry **) & ent[cache->nlibs];
  dep = (uint32_t *) & cache->entry[cache->nlibs];
  string_start = ((long) dep) - ((long) cache)
		 + cache->ndeps * sizeof (uint32_t);
  for (i = 0; i < cache->nlibs; i++)
    {
      /* Sanity checks.  */
      if (cache->entry[i].filename < string_start
	  || cache->entry[i].filename >= string_start + cache->len_strings
	  || cache->entry[i].depends >= cache->ndeps)
	error (EXIT_FAILURE, 0, "%s: bogus prelink cache file",
	       prelink_cache);

      ent[i].filename = ((char *) cache) + cache->entry[i].filename;
      ent[i].timestamp = cache->entry[i].timestamp;
      ent[i].id = cache->entry[i].id;
      ent[i].base = cache->entry[i].base;
      ent[i].end = cache->entry[i].end;
      if (stat64 (ent[i].filename, &st) < 0)
	ent[i].filename = NULL;
      else
	{
	  ent[i].dev = st.st_dev;
	  ent[i].ino = st.st_ino;
	}
    }

  for (i = 0; i < cache->nlibs; i++)
    {
      ent[i].depends = depends;
      for (j = cache->entry[i].depends; dep[j] != i; j++)
	{
	  if (dep[j] >= cache->nlibs)
	    error (EXIT_FAILURE, 0, "%s: bogus prelink cache file",
		   prelink_cache);
	  *depends++ = & ent[dep[j]];
	}
      ent[i].ndepends = j - cache->entry[i].depends;
      if (! ent[i].ndepends)
	ent[i].depends = NULL;
    }
  while (changed)
    {
      changed = 0;
      for (i = 0; i < cache->nlibs; i++)
	for (j = 0; j < ent[i].ndepends; j++)
	  if (ent[i].depends[j]->filename == NULL)
	    {
	      ent[i].filename = NULL;
	      changed = 1;
	      break;
	    }
    }
  for (i = 0; i < cache->nlibs; i++)
    if (ent[i].filename)
      ent[i].filename = strdup (ent[i].filename);
  for (i = 0; i < cache->nlibs; i++)
    if (ent[i].filename != NULL)
      break;
  if (i != cache->nlibs)
    {
      /* Build a chain.  */
      prelinked = ent + i;
      for (j = i + 1; j < cache->nlibs; j++)
	if (ent[j].filename != NULL)
	  {
	    ent[i].next = & ent[j];
	    i = j;
	  }
    }
  munmap (cache, cache_size);
  close (fd);
  return 0;
}

int
prelink_print_cache (void)
{
  struct prelink_entry *ent;
  int nlibs = 0, i;

  for (ent = prelinked; ent; ent = ent->next)
    nlibs++;

  printf ("%d libs found in prelink cache `%s'\n", nlibs, prelink_cache);
  for (ent = prelinked; ent; ent = ent->next)
    {
      printf ("%s[0x%08x 0x%08x] 0x%08llx-0x%08llx%s\n", ent->filename, ent->id,
	      ent->timestamp, (unsigned long long) ent->base,
	      (unsigned long long) ent->end, ent->ndepends ? ":" : "");
      for (i = 0; i < ent->ndepends; i++)
	printf ("    %s[0x%08x 0x%08x]\n", ent->depends[i]->filename,
		ent->depends[i]->id, ent->depends[i]->timestamp);
    }
  return 0;
}

int
prelink_save_cache (void)
{
  struct prelink_cache cache;
  struct prelink_entry *ent, **ents;
  struct prelink_cache_entry *data;
  uint32_t *deps, ndeps = 0, i, j, k;
  char *strings;
  int fd, len;

  memset (&cache, 0, sizeof (cache));
  memcpy ((char *) & cache, PRELINK_CACHE_MAGIC,
	  sizeof (PRELINK_CACHE_MAGIC) - 1);
  for (ent = prelinked; ent; ent = ent->next)
    {
      cache.nlibs++;
      cache.ndeps += ent->ndepends + 1;
      cache.len_strings += strlen (ent->filename) + 1;
    }

  len = cache.nlibs * sizeof (struct prelink_cache_entry)
	+ cache.ndeps * sizeof (uint32_t) + cache.len_strings;
  data = alloca (len);
  ents = alloca (cache.nlibs * sizeof (struct prelink_entry *));
  deps = (uint32_t *) & data[cache.nlibs];
  strings = (char *) & deps[cache.ndeps];

  for (i = 0, ent = prelinked; ent; ent = ent->next, i++)
    {
      data[i].filename = (strings - (char *) data) + sizeof (cache);
      strings = stpcpy (strings, ent->filename) + 1;
      ents[i] = ent;
      data[i].timestamp = ent->timestamp;
      data[i].id = ent->id;
      data[i].base = ent->base;
      data[i].end = ent->end;
    }

  for (i = 0; i < cache.nlibs; i++)
    {
      data[i].depends = ndeps;
      for (j = 0; j < ents[i]->ndepends; j++)
	{
	  for (k = 0; k < cache.nlibs; k++)
	    if (ents[k] == ents[i]->depends[j])
	      break;
	  if (k == cache.nlibs)
	    abort ();
	  deps[ndeps++] = k;
	}
      deps[ndeps++] = i;
    }

  fd = open (prelink_cache, O_WRONLY | O_CREAT, 0644);
  if (fd < 0)
    {
      error (0, errno, "Could not write prelink cache");
      return 1;
    }

  if (write (fd, &cache, sizeof (cache)) != sizeof (cache)
      || write (fd, data, len) != len
      || close (fd))
    {
      error (0, errno, "Could not write prelink cache");
      return 1;
    }
  return 0;
}

int prelink_find_cmp (const void *pa, const void *pb)
{
  struct prelink_entry **a = (struct prelink_entry **) pa;
  struct prelink_entry **b = (struct prelink_entry **) pb;

  if ((*a)->base < (*b)->base)
    return -1;
  if ((*a)->base > (*b)->base)
    return 1;
  return 0;
}

GElf_Addr
prelink_find_base (DSO *dso)
{
  int nlibs, i;
  struct prelink_entry *ent, **ents;
  GElf_Addr last, end;

  if (! prelinked)
    return dso->arch->mmap_base;

  for (nlibs = 0, ent = prelinked; ent; ent = ent->next)
    nlibs++;

  ents = alloca (nlibs * sizeof (struct prelink_entry *));
  for (i = 0, ent = prelinked; ent; ent = ent->next)
    ents[i++] = ent;
  qsort (ents, nlibs, sizeof (struct prelink_entry *), prelink_find_cmp);
  last = dso->arch->mmap_base;
  for (i = 0; i < nlibs; i++)
    {
      last = (last + dso->align - 1) & ~(dso->align - 1);
      end = last + dso->end - dso->base;
      if (end + 32768 <= ents[i]->base)
	return last;
      last = ents[i]->end + 32768;
    }
  last = (last + dso->align - 1) & ~(dso->align - 1);
  return last;
}

