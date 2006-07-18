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
#include <ftw.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "prelinktab.h"
#include "reloc.h"

static int gather_lib (struct prelink_entry *ent);
static int implicit;

struct prelink_dir *dirs;

static int
gather_deps (DSO *dso, struct prelink_entry *ent)
{
  int i;
  FILE *f;
  const char *argv[5];
  const char *envp[2];
  char *line = NULL, *p, *q = NULL;
  const char **depends = NULL;
  size_t ndepends = 0, ndepends_alloced = 0;
  size_t len = 0;
  ssize_t n;
  Elf_Scn *scn;
  Elf_Data *data;
  Elf32_Lib *liblist = NULL;
  int nliblist = 0;

  ent->soname = strdup (dso->soname);
  if (ent->soname == NULL)
    {
      error (0, ENOMEM, "%s: Could not record SONAME", ent->filename);
      goto error_out;
    }

  if (strcmp (dso->filename, dynamic_linker) == 0
      || is_ldso_soname (dso->soname))
    {
      if (ent->timestamp && ent->checksum)
	ent->done = 2;
      close_dso (dso);
      return 0;
    }

  for (i = 1; i < dso->ehdr.e_shnum; ++i)
    {
      const char *name
	= strptr (dso, dso->ehdr.e_shstrndx, dso->shdr[i].sh_name);
      if (! strcmp (name, ".gnu.liblist")
	  && (dso->shdr[i].sh_size % sizeof (Elf32_Lib)) == 0)
	{
	  nliblist = dso->shdr[i].sh_size / sizeof (Elf32_Lib);
	  liblist = (Elf32_Lib *) alloca (dso->shdr[i].sh_size);
	  scn = elf_getscn (dso->elf, i);
	  data = elf_getdata (scn, NULL);
	  if (data == NULL || elf_getdata (scn, data)
	      || data->d_buf == NULL || data->d_off
	      || data->d_size != dso->shdr[i].sh_size)
	    liblist = NULL;
	  else
	    memcpy (liblist, data->d_buf, dso->shdr[i].sh_size);
	  break;
	}
    }

  close_dso (dso);
  dso = NULL;

  i = 0;
  argv[i++] = dynamic_linker;
  if (ld_library_path)
    {
      argv[i++] = "--library-path";
      argv[i++] = ld_library_path;
    }
  argv[i++] = ent->filename;
  argv[i] = NULL;
  envp[0] = "LD_TRACE_LOADED_OBJECTS=1";
  envp[1] = NULL;
  f = execve_open (dynamic_linker, (char * const *)argv, (char * const *)envp);
  if (f == NULL)
    return 1;

  do
    {
      n = getline (&line, &len, f);
      if (n < 0)
        break;

      if (line[n - 1] == '\n')
        line[n - 1] = '\0';

      p = strstr (line, " => ");
      if (p)
	{
	  q = strstr (p, " (");
	  if (q == NULL && strcmp (p, " => not found") == 0)
	    {
	      error (0, 0, "%s: Could not find one of dependencies",
		     ent->filename);
	      goto error_out;
	    }
	}
      if (p == NULL || q == NULL)
	{
	  if (strstr (line, "statically linked") != NULL)
	    error (0, 0, "%s: Library without dependencies", ent->filename);
	  else
	    error (0, 0, "%s: Could not parse `%s'", ent->filename, line);
	  goto error_out;
	}

      *p = '\0';
      p += sizeof " => " - 1;
      *q = '\0';
      if (ndepends == ndepends_alloced)
	{
	  ndepends_alloced += 10;
	  depends =
	    (const char **) realloc (depends,
				     ndepends_alloced * sizeof (char *));
	  if (depends == NULL)
	    {
	      error (0, ENOMEM, "%s: Could not record dependencies",
		     ent->filename);
	      goto error_out;
	    }
	}

      depends[ndepends] = strdupa (p);
      ++ndepends;
    } while (!feof (f));

  if (execve_close (f))
    {
      error (0, 0, "%s: Dependency tracing failed", ent->filename);
      goto error_out;
    }

  free (line);
  line = NULL;

  ent->depends =
    (struct prelink_entry **)
    malloc (ndepends * sizeof (struct prelink_entry *));
  if (ent->depends == NULL)
    {
      error (0, ENOMEM, "%s: Could not record dependencies", ent->filename);
      goto error_out;
    }

  ent->ndepends = ndepends;
  for (i = 0; i < ndepends; ++i)
    {
      ent->depends[i] = prelink_find_entry (depends [i], 0, 0, 1);
      if (ent->depends[i] == NULL)
	goto error_out;

      if (ent->depends[i]->type != ET_NONE
	  && ent->depends[i]->type != ET_BAD
	  && ent->depends[i]->type != ET_DYN)
	{
	  error (0, 0, "%s is not a shared library", depends [i]);
	  goto error_out;
	}
    }

  free (depends);
  depends = NULL;

  for (i = 0; i < ndepends; ++i)
    if (ent->depends[i]->type == ET_NONE
	&& gather_lib (ent->depends[i]))
      goto error_out;

  if (liblist && nliblist == ndepends)
    {
      for (i = 0; i < ndepends; ++i)
	if (liblist[i].l_time_stamp != ent->depends[i]->timestamp
	    || liblist[i].l_checksum != ent->depends[i]->checksum
	    || ! ent->depends[i]->done)
	  break;

      if (i == ndepends)
        ent->done = 2;
    }

  return 0;

error_out:
  free (line);
  free (ent->depends);
  ent->depends = NULL;
  ent->ndepends = 0;
  free (depends);
  if (dso)
    close_dso (dso);
  return 1;
}

static int
gather_dso (DSO *dso, struct prelink_entry *ent)
{
  if (dso->ehdr.e_type != ET_DYN)
    {
      error (0, 0, "%s is not a shared library", ent->filename);
      close_dso (dso);
      return 1;
    }

  ent->timestamp = dso->info_DT_GNU_PRELINKED;
  ent->checksum = dso->info_DT_CHECKSUM;
  ent->base = dso->base;
  ent->end = dso->end;
  if (dso->arch->need_rel_to_rela != NULL
      && ent->timestamp == 0)
    {
      /* If the library has not been prelinked yet and we need
	 to convert REL to RELA, then make room for it.  */
      struct reloc_info rinfo;
      GElf_Addr adjust = 0;
      int sec = dso->ehdr.e_shnum;

      if (find_reloc_sections (dso, &rinfo))
	{
	  close_dso (dso);
	  return 1;
	}

      assert (sizeof (Elf32_Rel) * 3 == sizeof (Elf32_Rela) * 2);
      assert (sizeof (Elf64_Rel) * 3 == sizeof (Elf64_Rela) * 2);
      if (rinfo.rel_to_rela)
	{
	  sec = rinfo.first;
	  adjust = (dso->shdr[rinfo.last].sh_addr
		    + dso->shdr[rinfo.last].sh_size
		    - dso->shdr[rinfo.first].sh_addr) / 2;
	}
      if (rinfo.rel_to_rela_plt)
	{
	  if (rinfo.plt < sec)
	    sec = rinfo.plt;
	  adjust += dso->shdr[rinfo.plt].sh_size / 2;
	}
      if (adjust)
        {
	  for (; sec < dso->ehdr.e_shnum; ++sec)
	    if (dso->shdr[sec].sh_flags
		& (SHF_ALLOC | SHF_WRITE | SHF_EXECINSTR))
	      {
		if (adjust & (dso->shdr[sec].sh_addralign - 1))
		  adjust = (adjust + dso->shdr[sec].sh_addralign - 1)
			   & ~(dso->shdr[sec].sh_addralign - 1);
	      }
	  ent->end += adjust;
        }
    }

  if (gather_deps (dso, ent))
    return 1;

  if (ent->done && (! ent->timestamp || ! ent->checksum))
    ent->done = 0;
  ent->type = ET_DYN;
  return 0;
}

static int
gather_lib (struct prelink_entry *ent)
{
  DSO *dso;

  ent->type = ET_BAD;
  dso = open_dso (ent->filename);
  if (dso == NULL)
    return 1;

  return gather_dso (dso, ent);
}

static int
gather_exec (DSO *dso, const struct stat64 *st)
{
  int i, j;
  Elf_Data *data;
  struct prelink_entry *ent;

  for (i = 0; i < dso->ehdr.e_phnum; ++i)
    if (dso->phdr[i].p_type == PT_INTERP)
      break;

  /* If there are no PT_INTERP segments, it is statically linked.  */
  if (i == dso->ehdr.e_phnum)
    goto error_out;

  j = addr_to_sec (dso, dso->phdr[i].p_vaddr);
  if (j == -1 || dso->shdr[j].sh_addr != dso->phdr[i].p_vaddr
      || dso->shdr[j].sh_type != SHT_PROGBITS)
    {
      error (0, 0, "%s: PT_INTERP segment not corresponding to .interp section",
	     dso->filename);
      goto error_out;
    }

  data = elf_getdata (elf_getscn (dso->elf, j), NULL);
  if (data == NULL)
    {
      error (0, 0, "%s: Could not read .interp section", dso->filename);
      goto error_out;
    }

  i = strnlen (data->d_buf, data->d_size);
  if (i == data->d_size)
    {
      error (0, 0, "%s: .interp section not zero terminated", dso->filename);
      goto error_out;
    }

  if (strcmp (dynamic_linker, data->d_buf) != 0)
    {
      error (0, 0, "%s: Using %s, not %s as dynamic linker", dso->filename,
	     (char *) data->d_buf, dynamic_linker);
      goto error_out;
    }

  ent = prelink_find_entry (dso->filename, st->st_dev, st->st_ino, 1);
  if (ent == NULL)
    goto error_out;

  assert (ent->type == ET_NONE);
  ent->u.explicit = 1;

  if (gather_deps (dso, ent))
    return 0;

  for (i = 0; i < ent->ndepends; ++i)
    ++ent->depends[i]->refs;

  ent->type = ET_EXEC;
  return 0;

error_out:
  if (dso)
    close_dso (dso);
  return 0;
}

static int
add_dir_to_dirlist (const char *name, dev_t dev, int flags)
{
  const char *canon_name;
  struct prelink_dir *dir;
  size_t len;

  canon_name = canonicalize_file_name (name);
  if (canon_name == NULL)
    {
      if (! all && implicit)
	return 0;
      error (0, errno, "Could not record directory %s", name);
    }

  len = strlen (canon_name);
  dir = malloc (sizeof (struct prelink_dir) + len + 1);
  if (dir == NULL)
    {
      error (0, ENOMEM, "Could not record directory %s", name);
      free ((char *) canon_name);
      return 1;
    }

  dir->next = dirs;
  dir->flags = flags;
  dir->dev = dev;
  dir->len = len;
  strcpy (dir->dir, canon_name);
  free ((char *) canon_name);
  dirs = dir;
  return 0;
}

static int
gather_func (const char *name, const struct stat64 *st, int type,
	     struct FTW *ftwp)
{
  unsigned char e_ident [EI_NIDENT + 2];

  if (type == FTW_F && S_ISREG (st->st_mode) && (st->st_mode & 0111))
    {
      int fd;
      DSO *dso;
      struct prelink_entry *ent;

      ent = prelink_find_entry (name, st->st_dev, st->st_ino, 0);
      if (ent != NULL)
	{
	  ent->u.explicit = 1;
	  return 0;
	}

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

      gather_exec (dso, st);
    }
  else if (type == FTW_D && ! all)
    return add_dir_to_dirlist (name, st->st_dev, FTW_CHDIR);

  return 0;
}

static int
gather_binlib (const char *name, const struct stat64 *st)
{
  unsigned char e_ident [EI_NIDENT + 2];
  int fd, type;
  DSO *dso;
  struct prelink_entry *ent;

  if (! S_ISREG (st->st_mode))
    {
      error (0, 0, "%s is not a regular file", name);
      return 1;
    }

  ent = prelink_find_entry (name, st->st_dev, st->st_ino, 0);
  if (ent != NULL)
    {
      ent->u.explicit = 1;
      return 0;
    }

  fd = open (name, O_RDONLY);
  if (fd == -1)
    {
      error (0, errno, "Could not open %s", name);
      return 1;
    }

  if (read (fd, e_ident, sizeof (e_ident)) != sizeof (e_ident))
    {
      error (0, errno, "Could not read ELF header from %s", name);
      close (fd);
      return 1;
    }

  /* Quickly find ET_EXEC/ET_DYN ELF binaries/libraries only.  */

  if (memcmp (e_ident, ELFMAG, SELFMAG) != 0)
    {
      error (0, 0, "%s is not an ELF object", name);
      close (fd);
      return 1;
    }

  switch (e_ident [EI_DATA])
    {
    case ELFDATA2LSB:
      if (e_ident [EI_NIDENT + 1] != 0)
	goto unsupported_type;
      type = e_ident [EI_NIDENT];
      break;
    case ELFDATA2MSB:
      if (e_ident [EI_NIDENT] != 0)
	goto unsupported_type;
      type = e_ident [EI_NIDENT + 1];
      break;
    default:
      goto unsupported_type;
    }

  if (type != ET_EXEC && type != ET_DYN)
    {
unsupported_type:
      error (0, 0, "%s is neither ELF executable nor ELF shared library", name);
      close (fd);
      return 1;
    }

  dso = fdopen_dso (fd, name);
  if (dso == NULL)
    return 0;

  if (type == ET_EXEC)
    {
      int i;

      for (i = 0; i < dso->ehdr.e_phnum; ++i)
	if (dso->phdr[i].p_type == PT_INTERP)
      break;

      /* If there are no PT_INTERP segments, it is statically linked.  */
      if (i == dso->ehdr.e_phnum)
	{
	  error (0, 0, "%s is statically linked", name);
	  close_dso (dso);
	  return 1;
	}

      return gather_exec (dso, st);
    }

  ent = prelink_find_entry (name, st->st_dev, st->st_ino, 1);
  if (ent == NULL)
    {
      close_dso (dso);
      return 1;
    }

  assert (ent->type == ET_NONE);
  ent->type = ET_BAD;
  return gather_dso (dso, ent);
}

int
gather_object (const char *name, int deref, int onefs)
{
  struct stat64 st;

  if (stat64 (name, &st) < 0)
    {
      if (implicit)
        return 0;
      error (0, errno, "Could not stat %s", name);
      return 1;
    }

  if (S_ISDIR (st.st_mode))
    {
      int flags = 0, ret;
      if (! deref) flags |= FTW_PHYS;
      if (onefs) flags |= FTW_MOUNT;

      if (! all && implicit && ! deref)
	return add_dir_to_dirlist (name, st.st_dev, flags);
      ++implicit;
      ret = nftw64 (name, gather_func, 20, flags);
      --implicit;
      return ret;
    }
  else
    return gather_binlib (name, &st);
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

  implicit = 1;
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

      ret = gather_object (p, deref, onefs);
      if (ret)
	{
	  ret = 1;
	  break;
	}

    } while (!feof (file));

  free (line);
  fclose (file);
  implicit = 0;
  return ret;
}

static int
gather_check_lib (void **p, void *info)
{
  struct prelink_entry *e = * (struct prelink_entry **) p;
    
  if (e->type != ET_DYN)
    return 1;

  if (! e->u.explicit)
    {
      struct prelink_dir *dir;
      const char *name;
      size_t len;

      if (all)
	{
	  error (0, 0, "%s is not present in any config file directories, nor was specified on command line",
		 e->canon_filename);
	  e->type = ET_BAD;
	  return 1;
	}

      name = strrchr (e->canon_filename, '/');
      if (name)
	--name;
      else
	name = e->canon_filename;
      len = name - e->canon_filename;

      for (dir = dirs; dir; dir = dir->next)
	if (((dir->flags == FTW_CHDIR && len >= dir->len)
	     || (dir->flags != FTW_CHDIR && len == dir->len))
	    && strncmp (dir->dir, e->canon_filename, len) == 0)
	  {
	    if (dir->flags == FTW_CHDIR)
	      break;
	    if ((dir->flags & FTW_MOUNT) && dir->dev != e->dev)
	      continue;
	    break;
	  }

      if (dir == NULL)
	{
	  error (0, 0, "%s is not present in any config file directories, nor was specified on command line",
		 e->canon_filename);
	  e->type = ET_BAD;
	  return 1;
	}
    }

  return 1;
}

int
gather_check_libs (void)
{
  struct prelink_dir *dir;
  void *f;

  htab_traverse (prelink_filename_htab, gather_check_lib, NULL);

  dir = dirs;
  while (dir != NULL)
    {
      f = dir;
      dir = dir->next;
      free (f);
    }

  dirs = NULL;
  return 0;
}
