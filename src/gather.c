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

#include <errno.h>
#include <error.h>
#include <fcntl.h>
#include <ftw.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "prelink.h"

static int
gather_exec (DSO *dso)
{
  int i, j;
  Elf_Data *data;

  for (i = 0; i < dso->ehdr.e_phnum; ++i)
    if (dso->phdr[i].p_type == PT_INTERP)
      break;

  /* If there are no PT_INTERP segments, it is statically linked.  */
  if (i == dso->ehdr.e_phnum)
    return 0;

  j = addr_to_sec (dso, dso->phdr[i].p_vaddr);
  if (j == -1 || dso->shdr[j].sh_addr != dso->phdr[i].p_vaddr
      || dso->shdr[j].sh_type != SHT_PROGBITS)
    {
      error (0, 0, "%s: PT_INTERP segment not corresponding to .interp section",
	     dso->filename);
      return 0;
    }

  data = elf_getdata (elf_getscn (dso->elf, j), NULL);
  if (data == NULL)
    {
      error (0, 0, "%s: Could not read .interp section", dso->filename);
      return 0;
    }

  i = strnlen (data->d_buf, data->d_size);
  if (i == data->d_size)
    {
      error (0, 0, "%s: .interp section not zero terminated", dso->filename);
      return 0;
    }

  if (strcmp (dynamic_linker, data->d_buf) != 0)
    {
      error (0, 0, "%s: Using %s, not %s as dynamic linker", dso->filename,
	     (char *) data->d_buf, dynamic_linker);
      return 0;
    }

  printf ("%s\n", dso->filename);
  return 0;
}

static int
gather_func (const char *name, const struct stat64 *stat, int type,
	     struct FTW *ftwp)
{
  unsigned char e_ident [EI_NIDENT + 2];

  if (type == FTW_F && S_ISREG (stat->st_mode) && (stat->st_mode & 0111))
    {
      int fd;
      DSO *dso;
  
      fd = open (name, O_RDONLY);
      if (fd == -1)
        return 0;

      if (read (fd, e_ident, sizeof (e_ident)) != sizeof (e_ident))
	{
close_it:
	  close (fd);
	  return 0;
	}

      /* Quickly find ET_EXEC ELF binaries only.  */

      if (memcmp (e_ident, ELFMAG, SELFMAG) != 0)
	goto close_it;

      switch (e_ident [EI_DATA])
	{
	case ELFDATA2LSB:
	  if (e_ident [EI_NIDENT] != ET_EXEC || e_ident [EI_NIDENT + 1] != 0)
	    goto close_it;
	  break;
	case ELFDATA2MSB:
	  if (e_ident [EI_NIDENT + 1] != ET_EXEC || e_ident [EI_NIDENT] != 0)
	    goto close_it;
	  break;
	default:
	  goto close_it;
	}

      dso = fdopen_dso (fd, name);
      if (dso == NULL)
	return 0;

      gather_exec (dso);
      close_dso (dso);
    }

  return 0;
}

int
gather_dir (const char *dir, int deref, int onefs)
{
  int flags = 0, ret;

  if (! deref) flags |= FTW_PHYS;
  if (onefs) flags |= FTW_MOUNT;
  ret = nftw64 (dir, gather_func, 20, flags);
  return ret;
}

int
gather_config (const char *config)
{
  FILE *file = fopen (config, "r");
  char *line = NULL;
  size_t len;
  int ret = 0;

  if (file == NULL)
    {
      error (0, errno, "Can't open configuration file %s", config);
      return 1;
    }

  do
    {
      ssize_t i = getline (&line, &len, file);
      int deref = 0;
      int onefs = 0;
      char *p;

      if (i < 0)
        break;
                            
      if (line[i - 1] == '\n')
	line[i - 1] = '\0';

      p = strchr (line, '#');
      if (p != NULL)
	*p = '\0';

      p = line + strspn (line, " \t");

      while (*p == '-')
	{
	  switch (p[1])
	    {
	    case 'h': deref = 1; break;
	    case 'l': onefs = 1; break;
	    default:
	      error (0, 0, "Unknown directory option `%s'\n", p);
	      break;
	    }
	  p = p + 2 + strspn (p + 2, " \t");
	}

      if (*p == '\0')
	continue;

      ret = gather_dir (p, deref, onefs);
      if (ret == -1 && errno == ENOENT)
	ret = 0;
      if (ret)
	{
	  ret = 1;
	  break;
	}

    } while (!feof (file));

  free (line);
  fclose (file);
  return ret;
}
