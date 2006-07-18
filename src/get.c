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
#include "prelink.h"

int
is_ldso_soname (const char *soname)
{
  if (! strcmp (soname, "ld-linux.so.2")
      || ! strcmp (soname, "ld.so.1")    
      || ! strcmp (soname, "ld-linux-ia64.so.2")
      || ! strcmp (soname, "ld64.so.1"))
    return 1;
  return 0;
}

static int
prelink_record_relocations (struct prelink_info *info, FILE *f)
{
  char buffer[8192];
  struct prelink_entry *ent;
  struct stat64 st;
  DSO *dso = info->dso;
  struct deps
    {
      struct prelink_entry *ent;
      char *soname;
      GElf_Addr start;
      GElf_Addr l_addr;
    } *deps = NULL;
  int ndeps = 0, nalloc = 0;
  char *r;
  int i;

  /* Record the dependencies.  */
  while ((r = fgets (buffer, 8192, f)) != NULL)
    {
      char *soname, *filename, *p, *q;
      GElf_Addr start = 0, l_addr = 0;
      unsigned long long l;

      if (buffer[0] != '\t' || (filename = strstr (buffer, " => ")) == NULL)
	break;
      soname = buffer + 1;
      p = strstr (filename + sizeof (" => "), " (0x");
      if (p != NULL)
	{
	  l = strtoull (p + sizeof (" (0x") - 1, &q, 16);
	  start = (GElf_Addr) l;
	  if (start != l || strncmp (q, ", 0x", sizeof (", 0x") - 1))
	    p = NULL;
	  else
	    {
	      l = strtoull (q + sizeof (", 0x") - 1, &q, 16);
	      l_addr = (GElf_Addr) l;
	      if (l_addr != l || strcmp (q, ")\n") || q[-1] == 'x')
		p = NULL;
	    }
	}
      if (p == NULL)
	{
	  p = strchr (buffer, '\n');
	  if (p != NULL)
	    *p = '\0';
	  error (0, 0, "Could not parse line `%s'", buffer);
	  goto error_out;
	}
      *filename = '\0';
      filename += sizeof (" => ") - 1;
      *p = '\0';
      for (ent = prelinked; ent; ent = ent->next)
	if (! strcmp (ent->filename, filename))
	  break;
      if (ent == NULL)
	{
	  /* Try harder...  */
	  if (stat64 (filename, &st) < 0)
	    {
	      error (0, errno, "%s: Could not stat", filename);
	      goto error_out;
	    }
	  for (ent = prelinked; ent; ent = ent->next)
	    if (ent->dev == st.st_dev && ent->ino == st.st_ino)
	      break;
	}
      if (ent == NULL)
	{
	  error (0, 0, "Could not find %s => %s in the list of prelinked libraries",
		 soname, filename);
	  goto error_out;
	}
      if (ndeps == nalloc)
	{
	  nalloc += 5;
	  deps = (struct deps *) realloc (deps, nalloc * sizeof (struct deps));
	}
      deps[ndeps].soname = strdup (soname);
      if (deps[ndeps].soname == NULL)
	{
	  error (0, ENOMEM, "Could not record `%s' SONAME", soname);
	  goto error_out;
	}
      deps[ndeps].ent = ent;
      deps[ndeps].start = start;
      deps[ndeps++].l_addr = l_addr;
    }
  if (ndeps == 0)
    {
      error (0, 0, "%s: %s did not print any library line", dso->filename,
	     dynamic_linker);
      goto error_out;
    }
  if (deps[0].ent != prelinked)
    {
      error (0, 0, "%s: %s did not print the traced object first", dso->filename,
	     dynamic_linker);
      goto error_out;
    }
  if (r == NULL)
    {
      error (0, 0, "%s: %s did not print any lookup lines", dso->filename,
	     dynamic_linker);
      goto error_out;
    }
  if (dso->ehdr.e_type == ET_EXEC)
    {
      info->conflicts = (struct prelink_conflict **)
			calloc (sizeof (struct prelink_conflict *), ndeps);
      if (info->conflicts == NULL)
	{
	  error (0, ENOMEM, "%s: Can't build list of conflicts", dso->filename);
	  goto error_out;
	}
    }
  do
    {
      unsigned long long symstart, symoff, valstart[3], value[3];
      int reloc_type, len;

      r = strchr (buffer, '\n');
      if (r)
	*r = '\0';
      if (strncmp (buffer, "lookup ", sizeof ("lookup ") - 1) == 0)
	{
	  struct prelink_symbol *s;

	  if (sscanf (buffer, "lookup 0x%llx 0x%llx -> 0x%llx 0x%llx %d %n",
		      &symstart, &symoff, &valstart[0], &value[0],
		      &reloc_type, &len) != 5 || reloc_type == 0)
	    {
	      error (0, 0, "%s: Could not parse `%s'", dso->filename, buffer);
	      goto error_out;
	    }

	  if (symstart != deps[0].start)
	    continue;

	  /* Only interested in relocations from the current object.  */
	  if (symoff < info->symtab_start || symoff >= info->symtab_end)
	    {
	      error (0, 0, "%s: Symbol `%s' offset 0x%08llx does not point into .dynsym section",
		     dso->filename, buffer + len, symoff);
	      goto error_out;
	    }
	  for (i = 0, ent = NULL; i < ndeps; i++)
	    if (deps[i].start == valstart[0])
	      {
		ent = deps[i].ent;
		/* If the library the symbol is bound to is already prelinked,
		   adjust the value so that it is relative to library
		   base.  */
		value[0] -= deps[i].start - deps[i].l_addr;
		break;
	      }
	  if (ent == NULL && valstart[0])
	    {
	      error (0, 0, "Could not find base 0x%08llx in the list of bases `%s'",
		     valstart[0], buffer);
	      goto error_out;
	    }
	  if (ent == info->ent)
	    value[0] = adjust_old_to_new (info->dso, value[0]);

	  s = &info->symbols[(symoff - info->symtab_start)
			      / info->symtab_entsize];
	  if (s->reloc_type)
	    {
	      while (s->reloc_type != reloc_type && s->next != NULL)
		s = s->next;
	      if (s->reloc_type == reloc_type)
		{
		  if (s->ent != ent || s->value != value[0])
		    {
		      error (0, 0, "%s: Symbol `%s' with the same reloc type resolves to different values each time",
			     dso->filename, buffer + len);
		      goto error_out;
		    }
		  s = NULL;
		}
	      else
		{
		  s->next = (struct prelink_symbol *)
			    malloc (sizeof (struct prelink_symbol));
		  if (s->next == NULL)
		    {
		      error (0, ENOMEM, "Cannot build symbol lookup map");
		      goto error_out;
		    }
		  s = s->next;
		}
	    }
	  if (s)
	    {
	      s->ent = ent;
	      s->value = value[0];
	      s->reloc_type = reloc_type;
	      s->next = NULL;
	    }
	}
      else if (strncmp (buffer, "conflict ", sizeof ("conflict ") - 1) == 0)
	{
	  if (sscanf (buffer, "conflict 0x%llx 0x%llx -> 0x%llx 0x%llx x 0x%llx 0x%llx %d %n",
		      &symstart, &symoff, &valstart[0], &value[0],
		      &valstart[1], &value[1], &reloc_type, &len) != 7
	      || reloc_type == 0)
	    {
	      error (0, 0, "%s: Could not parse `%s'", dso->filename, buffer);
	      goto error_out;
	    }

	  if (symstart == deps[0].start)
	    {
	      error (0, 0, "Conflict in _dl_loader `%s'", buffer);
	      goto error_out;
	    }

	  if (info->conflicts)
	    {
	      struct prelink_entry *ents[2];
	      struct prelink_conflict *conflict;
	      int symowner, j;

	      for (symowner = 1; symowner < ndeps; symowner++)
		if (deps[symowner].start == symstart)
		  break;
	      if (symowner == ndeps)
		{
		  error (0, 0, "Could not find base 0x%08llx in the list of bases `%s'",
			 symstart, buffer);
		  goto error_out;
		}
		
	      for (j = 0; j < 2; j++)
		{
		  for (i = 0, ent = NULL; i < ndeps; i++)
		    if (deps[i].start == valstart[j])
		      {
			ents[j] = deps[i].ent;
			/* If the library the symbol is bound to is already
			   prelinked, adjust the value so that it is relative
			   to library base.  */
			value[j] -= deps[i].start - deps[i].l_addr;
			break;
		      }
		  if (ents[j] == NULL && valstart[j])
		    {
		      error (0, 0, "Could not find base 0x%08llx in the list of bases `%s'",
			     valstart[j], buffer);
		      goto error_out;
		    }
		}

	      for (conflict = info->conflicts[symowner]; conflict;
		   conflict = conflict->next)
		if (conflict->symoff == symoff
		    && conflict->reloc_type == reloc_type)
		  {
		    if (conflict->lookupent != ents[0]
			|| conflict->conflictent != ents[1]
			|| conflict->lookupval != value[0]
			|| conflict->conflictval != value[1])
		      {
			error (0, 0, "%s: Symbol `%s' with the same reloc type resolves to different values each time",
			       dso->filename, buffer + len);
			goto error_out;
		      }
		    break;
		  }
	      if (conflict == NULL)
		{
		  conflict = malloc (sizeof (struct prelink_conflict));
		  if (conflict == NULL)
		    {
		      error (0, ENOMEM, "Cannot build list of conflicts");
		      goto error_out;
		    }

		  conflict->next = info->conflicts[symowner];
		  info->conflicts[symowner] = conflict;
		  conflict->lookupent = ents[0];
		  conflict->conflictent = ents[1];
		  conflict->lookupval = value[0];
		  conflict->conflictval = value[1];
		  conflict->symoff = symoff;
		  conflict->reloc_type = reloc_type;
		  conflict->used = 0;
		}
	    }
	}
    } while (fgets (buffer, 8192, f) != NULL);

  if (ndeps > 1)
    {
      prelinked->depends = malloc (sizeof (struct prelink_entry *)
				   * (ndeps - 1));
      if (prelinked->depends == NULL)
	{
	  error (0, ENOMEM, "Could not record dependencies");
	  goto error_out;
	}
      prelinked->ndepends = ndeps - 1;
      for (i = 1; i < ndeps; i++)
	prelinked->depends[i - 1] = deps[i].ent;
    }

  info->sonames = malloc (ndeps * sizeof (const char *));
  for (i = 0; i < ndeps; i++)
    info->sonames[i] = deps[i].soname;

  free (deps);
  return 0;

error_out:
  free (info->conflicts);
  info->conflicts = NULL;
  for (i = 0; i < ndeps; i++)
    free (deps[i].soname);
  free (deps);
  return 1;
}

int
prelink_get_relocations (struct prelink_info *info)
{
  char *command;
  FILE *f;
  struct prelink_entry *ent;
  struct stat64 st;
  DSO *dso = info->dso;
  int ret, status;

  ent = (struct prelink_entry *) calloc (sizeof (struct prelink_entry), 1);
  ent->filename = strdup (dso->filename);
  ent->soname = strdup (dso->soname);
  ent->timestamp = 0;
  ent->checksum = 0;
  ent->base = dso->base;
  ent->end = dso->end;
  if (stat64 (ent->filename, &st) < 0)
    {
      error (0, errno, "%s: Could not stat", ent->filename);
      return 0;
    }
  ent->dev = st.st_dev;
  ent->ino = st.st_ino;
  ent->next = prelinked;
  prelinked = ent;
  info->ent = ent;

  if (is_ldso_soname (info->dso->soname))
    return 1;
  if (strchr (info->dso->filename, '\''))
    {
      error (0, 0, "%s: Filename containing single quotes not supported",
	     info->dso->filename);
      return 0;
    }

  if (dynamic_linker == NULL)
    dynamic_linker = "/lib/ld-linux.so.2"; /* FIXME.  */
  if (ld_library_path == NULL)
    {
      ld_library_path = getenv ("LD_LIBRARY_PATH");
      if (ld_library_path == NULL)
        ld_library_path = "";
    }
  command = alloca (strlen (dynamic_linker) + strlen (info->dso->filename) + strlen (ld_library_path)
		    + sizeof ("LD_LIBRARY_PATH=%s LD_TRACE_LOADED_OBJECTS=1 LD_TRACE_PRELINKING=1 LD_BIND_NOW=1 %s '%s' 2>&1") - 1);
  sprintf (command, "LD_LIBRARY_PATH=%s %s --verify '%s' >/dev/null", ld_library_path, dynamic_linker,
	   info->dso->filename);
  ret = system (command);
  if (ret == -1 || ! WIFEXITED (ret) || (WEXITSTATUS (ret) & ~2))
    {
      error (0, 0, "%s: Statically linked or not supported by %s dynamic linker",
	     info->dso->filename, dynamic_linker);
      return 0;
    }
  ret = 2;

  info->symbols = calloc (sizeof (struct prelink_symbol),
			  (info->symtab_end - info->symtab_start)
			  / info->symtab_entsize);

  sprintf (command, "LD_LIBRARY_PATH=%s LD_TRACE_LOADED_OBJECTS=1 LD_TRACE_PRELINKING=%s LD_BIND_NOW=1 %s '%s' 2>&1",
	   ld_library_path, info->dso->filename, dynamic_linker,
	   info->dso->filename);

  f = popen (command, "r");
  if (f == NULL)
    {
      error (0, errno, "%s: Could not trace symbol resolving",
	     info->dso->filename);
      return 0;
    }
  if (prelink_record_relocations (info, f))
    ret = 0;
  status = pclose (f);
  if (status == -1 || ! WIFEXITED (status) || WEXITSTATUS (status))
    {
      if (ret)
	{
	  error (0, status == -1 ? errno : 0,
		 "%s Could not trace symbol resolving", info->dso->filename);
	}
      return 0;
    }
  return ret;
}
