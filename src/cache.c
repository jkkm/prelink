/* Copyright (C) 2001, 2002 Red Hat, Inc.
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
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include "prelinktab.h"

htab_t prelink_devino_htab, prelink_filename_htab;

int prelink_entry_count;

static hashval_t
devino_hash (const void *p)
{
  struct prelink_entry *e = (struct prelink_entry *)p;

  return (e->dev << 2) ^ (e->ino) ^ (e->ino >> 20);
}

static int
devino_eq (const void *p, const void *q)
{
  struct prelink_entry *e = (struct prelink_entry *)p;
  struct prelink_entry *f = (struct prelink_entry *)q;

  return e->ino == f->ino && e->dev == f->dev;
}

static hashval_t
filename_hash (const void *p)
{
  struct prelink_entry *e = (struct prelink_entry *)p;
  const unsigned char *s = (const unsigned char *)e->filename;
  hashval_t h = 0;
  unsigned char c;
  size_t len = 0;

  while ((c = *s++) != '\0')
    {
      h += c + (c << 17);
      h ^= h >> 2;
      ++len;
    }
  return h + len + (len << 17);
}

static int
filename_eq (const void *p, const void *q)
{
  struct prelink_entry *e = (struct prelink_entry *)p;
  struct prelink_entry *f = (struct prelink_entry *)q;

  return strcmp (e->filename, f->filename) == 0;
}

int
prelink_init_cache (void)
{
  prelink_devino_htab = htab_try_create (100, devino_hash, devino_eq, NULL);
  prelink_filename_htab = htab_try_create (100, filename_hash, filename_eq,
					   NULL);
  if (prelink_devino_htab == NULL || prelink_filename_htab == NULL)
    error (EXIT_FAILURE, ENOMEM, "Could not create hash table");
  return 0;
}

struct prelink_entry *
prelink_find_entry (const char *filename, dev_t dev, ino64_t ino, int insert)
{
  struct prelink_entry e, *ent = NULL;
  void **filename_slot;
  void **devino_slot;

  e.filename = filename;
  filename_slot = htab_find_slot (prelink_filename_htab, &e, INSERT);
  if (filename_slot == NULL)
    goto error_out;

  if (*filename_slot != NULL)
    return (struct prelink_entry *) *filename_slot;

  if (! dev)
    {
      struct stat64 st;

      if (stat64 (filename, &st) < 0)
	{
	  error (0, errno, "Could not stat %s", filename);
	  return NULL;
	}
      dev = st.st_dev;
      ino = st.st_ino;
    }

  e.dev = dev;
  e.ino = ino;
  devino_slot = htab_find_slot (prelink_devino_htab, &e, INSERT);
  if (devino_slot == NULL)
    goto error_out;

  if (*devino_slot != NULL)
    {
      char *canon_filename;

      ent = (struct prelink_entry *) *devino_slot;
      canon_filename = canonicalize_file_name (filename);
      if (canon_filename == NULL)
	{
	  error (0, 0, "Could not canonicalize filename %s", filename);
	  return NULL;
	}

      if (strcmp (canon_filename, ent->canon_filename) != 0)
        {
	  struct prelink_link *hardlink;

	  hardlink = (struct prelink_link *)
		     malloc (sizeof (struct prelink_link));
	  if (hardlink == NULL)
	    {
	      error (0, ENOMEM, "Could not record hardlink %s to %s",
		     canon_filename, ent->canon_filename);
	      free (canon_filename);
	      return NULL;
	    }

	  hardlink->canon_filename = canon_filename;
	  hardlink->next = ent->hardlink;
	  ent->hardlink = hardlink;
        }
      else
        free (canon_filename);
      return ent;
    }

  if (! insert)
    return NULL;

  ent = (struct prelink_entry *) calloc (sizeof (struct prelink_entry), 1);
  if (ent == NULL)
    goto error_out;

  ent->filename = strdup (filename);
  if (ent->filename == NULL)
    goto error_out;

  ent->canon_filename = canonicalize_file_name (filename);
  if (ent->canon_filename == NULL)
    {
      error (0, 0, "Could not canonicalize filename %s", filename);
      return NULL;
    }

  ent->dev = dev;
  ent->ino = ino;
  *filename_slot = ent;
  *devino_slot = ent;
  ++prelink_entry_count;
  return ent;

error_out:
  free (ent);
  error (0, ENOMEM, "Could not insert %s into hash table", filename);
  return NULL;
}

static struct prelink_entry *
prelink_load_entry (const char *filename)
{
  struct prelink_entry e, *ent = NULL;
  void **filename_slot;
  void **devino_slot, *dummy = NULL;
  struct stat64 st;

  e.filename = filename;
  filename_slot = htab_find_slot (prelink_filename_htab, &e, INSERT);
  if (filename_slot == NULL)
    goto error_out;

  if (*filename_slot != NULL)
    return (struct prelink_entry *) *filename_slot;

  if (stat64 (filename, &st) < 0)
    {
      e.dev = 0;
      e.ino = 0;
      devino_slot = &dummy;
    }
  else
    {
      e.dev = st.st_dev;
      e.ino = st.st_ino;
      devino_slot = htab_find_slot (prelink_devino_htab, &e, INSERT);
      if (devino_slot == NULL)
	goto error_out;
    }

  if (*devino_slot != NULL)
    return (struct prelink_entry *) *devino_slot;

  ent = (struct prelink_entry *) calloc (sizeof (struct prelink_entry), 1);
  if (ent == NULL)
    goto error_out;

  ent->filename = strdup (filename);
  if (ent->filename == NULL)
    goto error_out;

  ent->canon_filename = strdup (filename);
  if (ent->canon_filename == NULL)
    {
      free ((char *) ent->filename);
      goto error_out;
    }

  ent->dev = e.dev;
  ent->ino = e.ino;
  *filename_slot = ent;
  *devino_slot = ent;
  ++prelink_entry_count;
  return ent;

error_out:
  free (ent);
  error (0, ENOMEM, "Could not insert %s into hash table", filename);
  return NULL;
}

int
prelink_load_cache (void)
{
  int fd, i, j;
  struct stat64 st;
  struct prelink_cache *cache;
  struct prelink_entry **ents;
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
  dep = (uint32_t *) & cache->entry[cache->nlibs];
  string_start = ((long) dep) - ((long) cache)
		 + cache->ndeps * sizeof (uint32_t);
  ents = (struct prelink_entry **)
	 alloca (cache->nlibs * sizeof (struct prelink_entry *));
  memset (ents, 0, cache->nlibs * sizeof (struct prelink_entry *));
  for (i = 0; i < cache->nlibs; i++)
    {
      /* Sanity checks.  */
      if (cache->entry[i].filename < string_start
	  || cache->entry[i].filename >= string_start + cache->len_strings
	  || cache->entry[i].depends >= cache->ndeps)
	error (EXIT_FAILURE, 0, "%s: bogus prelink cache file",
	       prelink_cache);

      ents[i] = prelink_load_entry (((char *) cache)
				    + cache->entry[i].filename);
      if (ents[i] == NULL)
	error (EXIT_FAILURE, ENOMEM, "Cannot read cache file %s",
	       prelink_cache);
    }

  for (i = 0; i < cache->nlibs; i++)
    {
      if (ents[i]->type != ET_NONE)
	continue;

      ents[i]->checksum = cache->entry[i].checksum;
      ents[i]->base = cache->entry[i].base;
      ents[i]->end = cache->entry[i].end;
      ents[i]->type = (ents[i]->base == 0 && ents[i]->end == 0)
		      ? ET_CACHE_EXEC : ET_CACHE_DYN;
      ents[i]->flags = cache->entry[i].flags;

      for (j = cache->entry[i].depends; dep[j] != i; ++j)
	if (dep[j] >= cache->nlibs)
	  error (EXIT_FAILURE, 0, "%s: bogus prelink cache file",
		 prelink_cache);

      ents[i]->ndepends = j - cache->entry[i].depends;
      if (ents[i]->ndepends)
	{
	  ents[i]->depends =
	    (struct prelink_entry **)
	    malloc (ents[i]->ndepends * sizeof (struct prelink_entry *));
	  if (ents[i]->depends == NULL)
	    error (EXIT_FAILURE, ENOMEM, "Cannot read cache file %s",
		   prelink_cache);

	  for (j = 0; j < ents[i]->ndepends; ++j)
	    ents[i]->depends[j] = ents[dep[cache->entry[i].depends + j]];
	}
    }

  munmap (cache, cache_size);
  close (fd);
  return 0;
}

static int
prelink_print_cache_size (void **p, void *info)
{
  struct prelink_entry *e = * (struct prelink_entry **) p;
  int *psize = (int *) info;

  if ((e->base & 0xffffffff) != e->base
      || (e->end & 0xffffffff) != e->end)
    {
      *psize = 16;
      return 0;
    }

  return 1;
}  

static int
prelink_print_cache_object (void **p, void *info)
{
  struct prelink_entry *e = * (struct prelink_entry **) p;
  int *psize = (int *) info, i;

  if (e->type == ET_CACHE_DYN)
    printf ("%s [0x%08x] 0x%0*llx-0x%0*llx%s\n", e->filename, e->checksum,
	    *psize, (long long) e->base, *psize, (long long) e->end,
	    e->ndepends ? ":" : "");
  else
    printf ("%s%s\n", e->filename, e->ndepends ? ":" : "");
  for (i = 0; i < e->ndepends; i++)
    printf ("    %s [0x%08x]\n", e->depends[i]->filename,
	    e->depends[i]->checksum);
  return 1;
}

int
prelink_print_cache (void)
{
  int size = 8;

  printf ("%d objects found in prelink cache `%s'\n", prelink_entry_count,
	  prelink_cache);

  htab_traverse (prelink_filename_htab, prelink_print_cache_size, &size);
  htab_traverse (prelink_filename_htab, prelink_print_cache_object, &size);
  return 0;
}

struct collect_ents
{
  struct prelink_entry **ents;
  size_t len_strings;
  int nents;
  int ndeps;
};

static int
prelink_save_cache_check (struct prelink_entry *ent)
{
  int i;

  for (i = 0; i < ent->ndepends; ++i)
    switch (ent->depends[i]->type)
      {
      case ET_DYN:
	if (ent->depends[i]->done < 2)
	  return 1;
	break;
      case ET_CACHE_DYN:
	if (prelink_save_cache_check (ent->depends[i]))
	  return 1;
	break;
      default:
	return 1;
      }

  return 0;
}

static int
find_ents (void **p, void *info)
{
  struct collect_ents *l = (struct collect_ents *) info;
  struct prelink_entry *e = * (struct prelink_entry **) p;

  if (((e->type == ET_DYN || (conserve_memory && e->type == ET_EXEC))
       && e->done == 2)
      || ((e->type == ET_CACHE_DYN || e->type == ET_CACHE_EXEC)
	  && ! prelink_save_cache_check (e)))
    {
      l->ents[l->nents++] = e;
      l->ndeps += e->ndepends + 1;
      l->len_strings += strlen (e->canon_filename) + 1;
    }
  return 1;
}

int
prelink_save_cache (int do_warn)
{
  struct prelink_cache cache;
  struct collect_ents l;
  struct prelink_cache_entry *data;
  uint32_t *deps, ndeps = 0, i, j, k;
  char *strings;
  int fd, len;

  memset (&cache, 0, sizeof (cache));
  memcpy ((char *) & cache, PRELINK_CACHE_MAGIC,
	  sizeof (PRELINK_CACHE_MAGIC) - 1);
  l.ents =
    (struct prelink_entry **) alloca (prelink_entry_count
				      * sizeof (struct prelink_entry *));
  l.nents = 0;
  l.ndeps = 0;
  l.len_strings = 0;
  htab_traverse (prelink_filename_htab, find_ents, &l);
  cache.nlibs = l.nents;
  cache.ndeps = l.ndeps;
  cache.len_strings = l.len_strings;  

  len = cache.nlibs * sizeof (struct prelink_cache_entry)
	+ cache.ndeps * sizeof (uint32_t) + cache.len_strings;
  data = alloca (len);
  deps = (uint32_t *) & data[cache.nlibs];
  strings = (char *) & deps[cache.ndeps];

  for (i = 0; i < l.nents; ++i)
    {
      data[i].filename = (strings - (char *) data) + sizeof (cache);
      strings = stpcpy (strings, l.ents[i]->canon_filename) + 1;
      data[i].checksum = l.ents[i]->checksum;
      data[i].flags = l.ents[i]->flags;
      if (l.ents[i]->type == ET_EXEC || l.ents[i]->type == ET_CACHE_EXEC)
	{
	  data[i].base = 0;
	  data[i].end = 0;
	}
      else
	{
	  data[i].base = l.ents[i]->base;
	  data[i].end = l.ents[i]->end;
	}
    }

  for (i = 0; i < cache.nlibs; i++)
    {
      data[i].depends = ndeps;
      for (j = 0; j < l.ents[i]->ndepends; j++)
	{
	  for (k = 0; k < cache.nlibs; k++)
	    if (l.ents[k] == l.ents[i]->depends[j])
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

#ifndef NDEBUG
static void
prelink_entry_dumpfn (FILE *f, const void *ptr)
{
  struct prelink_entry *e = (struct prelink_entry *) ptr;
  struct prelink_link *l;
  int i;

  fprintf (f, "%s|%s|%s|%x|%x|%llx|%llx|%llx|%llx|%llx|%d|%d|%d|%d|%d|%d|%d|",
	   e->filename,
	   strcmp (e->canon_filename, e->filename) ? e->canon_filename : "",
	   strcmp (e->soname, e->filename) ? e->soname : "",
	   e->timestamp, e->checksum,
	   (long long) e->base, (long long) e->end, (long long) e->pltgot,
	   (long long) e->dev, (long long) e->ino,
	   e->type, e->done, e->ndepends, e->refs, e->flags,
	   e->prev ? e->prev->u.tmp : -1, e->next ? e->next->u.tmp : -1);
  for (i = 0; i < e->ndepends; ++i)
    fprintf (f, "%d-", e->depends [i]->u.tmp);
  fputc ('|', f);
  for (l = e->hardlink; l; l = l->next)
    fprintf (f, "%s|", l->canon_filename);
  fputs ("\n", f);
}

void
prelink_entry_dump (htab_t htab, const char *filename)
{
  size_t i;

  for (i = 0; i < htab->size; ++i)
    if (htab->entries [i] && htab->entries [i] != (void *) 1)
      ((struct prelink_entry *) htab->entries [i])->u.tmp = i;
  htab_dump (htab, filename, prelink_entry_dumpfn);
}

static char *restore_line;
static size_t restore_size;

static void *
prelink_entry_restorefn (FILE *f)
{
  struct prelink_entry *e;
  struct prelink_link **plink;
  char *p, *q, *s;
  long long ll[5];
  int ii[5];
  int i;

  if (getline (&restore_line, &restore_size, f) < 0)
    abort ();
  e = (struct prelink_entry *) calloc (1, sizeof (struct prelink_entry));
  if (e == NULL)
    abort ();
  p = restore_line;
  q = strchr (p, '|');
  s = malloc (q - p + 1);
  memcpy (s, p, q - p);
  s [q - p] = '\0';
  e->filename = s;
  ++q;
  p = q;
  if (*p == '|')
    e->canon_filename = strdup (e->filename);
  else
    {
      q = strchr (p, '|');
      s = malloc (q - p + 1);
      memcpy (s, p, q - p);
      s [q - p] = '\0';
      e->canon_filename = s;
    }
  ++q;
  p = q;
  if (*p == '|')
    e->soname = strdup (e->filename);
  else
    {
      q = strchr (p, '|');
      s = malloc (q - p + 1);
      memcpy (s, p, q - p);
      s [q - p] = '\0';
      e->soname = s;
    }
  p = q + 1;
  if (sscanf (p, "%x|%x|%llx|%llx|%llx|%llx|%llx|%d|%d|%d|%d|%d|%d|%d|%n",
	      ii, ii + 1, ll, ll + 1, ll + 2, ll + 3, ll + 4,
	      &e->type, &e->done, &e->ndepends, &e->refs, &e->flags,
	      ii + 2, ii + 3, ii + 4) < 14)
    abort ();
  e->timestamp = ii[0];
  e->checksum = ii[1];
  e->base = ll[0];
  e->end = ll[1];
  e->pltgot = ll[2];
  e->dev = ll[3];
  e->ino = ll[4];
  e->prev = (void *) (long) ii[2];
  e->next = (void *) (long) ii[3];
  e->depends = (struct prelink_entry **)
	       malloc (e->ndepends * sizeof (struct prelink_entry *));
  p += ii[4];
  for (i = 0; i < e->ndepends; ++i)
    {
      e->depends [i] = (void *) strtol (p, &q, 0);
      if (p == q || *q != '-')
        abort ();
      p = q + 1;
    }
  if (*p++ != '|')
    abort ();
  plink = &e->hardlink;
  while (*p != '\n')
    {
      struct prelink_link *link = (struct prelink_link *)
				  malloc (sizeof (struct prelink_link));
      q = strchr (p, '|');
      *plink = link;
      plink = &link->next;
      s = malloc (q - p + 1);
      memcpy (s, p, q - p);
      s [q - p] = '\0';
      e->soname = s;
      link->canon_filename = s;
      p = q + 1;
    }
  *plink = NULL;
  return e;
}

void
prelink_entry_restore (htab_t htab, const char *filename)
{
  size_t i, j;
  struct prelink_entry *e;

  htab_restore (htab, filename, prelink_entry_restorefn);
  free (restore_line);
  for (i = 0; i < htab->size; ++i)
    if (htab->entries [i] && htab->entries [i] != (void *) 1)
      {
	e = (struct prelink_entry *) htab->entries [i];
	if (e->prev == (void *) -1)
	  e->prev = NULL;
	else
	  e->prev = (struct prelink_entry *)
		    htab->entries [(long) e->prev];
	if (e->next == (void *) -1)
	  e->next = NULL;
	else
	  e->next = (struct prelink_entry *)
		    htab->entries [(long) e->next];
	for (j = 0; j < e->ndepends; ++j)
	  {
	    e->depends [j] = (struct prelink_entry *)
			     htab->entries [(long) e->depends [j]];
	  }
      }
}
#endif
