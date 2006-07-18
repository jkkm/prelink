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
  DSO *dso = info->dso;
  struct prelink_entry *ent, *ent2;
  struct deps
    {
      struct prelink_entry *ent;
      char *soname;
      GElf_Addr start;
      GElf_Addr l_addr;
    } deps[info->ent->ndepends + 1];
  char *r;
  int i, ndeps = 0, undef = 0;

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

      if (ndeps > info->ent->ndepends)
        {
	  error (0, 0, "%s: Recorded %d dependencies, now seeing %d\n",
		 info->ent->filename, info->ent->ndepends, ndeps - 1);
	  goto error_out;
        }

      ent2 = ndeps ? info->ent->depends [ndeps - 1] : info->ent;
      if (strcmp (ent2->filename, filename) != 0
	  && strcmp (ent2->canon_filename, filename) != 0)
	{
	  struct prelink_link *hardlink;

	  for (hardlink = ent2->hardlink; hardlink; hardlink = hardlink->next)
	    if (strcmp (hardlink->canon_filename, filename) == 0)
	      break;

	  if (hardlink == NULL)
	    {
	      struct stat64 st;

	      if (stat64 (filename, &st) < 0)
		{
		  error (0, errno, "%s: Could not stat %s",
			 info->ent->filename, filename);
		  goto error_out;
		}

	      if (st.st_dev != info->ent->dev || st.st_ino != info->ent->ino)
	        {
		  error (0, 0, "%s: %s => %s does not match recorded dependency",
			 info->ent->filename, soname, filename);
		  goto error_out;
		}
	    }
	}

      if (! ndeps)
        deps[ndeps].ent = info->ent;
      else
        deps[ndeps].ent = info->ent->depends[ndeps - 1];
      deps[ndeps].soname = strdup (soname);
      if (deps[ndeps].soname == NULL)
	{
	  error (0, ENOMEM, "Could not record `%s' SONAME", soname);
	  goto error_out;
	}
      deps[ndeps].start = start;
      deps[ndeps++].l_addr = l_addr;
    }

  if (ndeps != info->ent->ndepends + 1)
    {
      error (0, 0, "%s: Recorded %d dependencies, now seeing %d\n",
	     info->ent->filename, info->ent->ndepends, ndeps - 1);
      goto error_out;
    }

  if (r == NULL)
    {
      error (0, 0, "%s: %s did not print any lookup lines", info->ent->filename,
	     dynamic_linker);
      goto error_out;
    }

  if (dso->ehdr.e_type == ET_EXEC)
    {
      info->conflicts = (struct prelink_conflict **)
			calloc (sizeof (struct prelink_conflict *), ndeps);
      if (info->conflicts == NULL)
	{
	  error (0, ENOMEM, "%s: Can't build list of conflicts", info->ent->filename);
	  goto error_out;
	}
    }
  do
    {
      unsigned long long symstart, symoff, valstart[3], value[3];
      int reloc_class, len, type = 1;
      char *symname;

      r = strchr (buffer, '\n');
      if (r)
	*r = '\0';
      if (strncmp (buffer, "lookup ", sizeof ("lookup ") - 1) == 0)
	{
	  struct prelink_symbol *s;

	  if (sscanf (buffer, "lookup 0x%llx 0x%llx -> 0x%llx 0x%llx %n",
		      &symstart, &symoff, &valstart[0], &value[0], &len) != 4)
	    {
	      error (0, 0, "%s: Could not parse `%s'", info->ent->filename, buffer);
	      goto error_out;
	    }

	  if (buffer[len] == '/')
	    {
	      ++len;
	      type = 0;
	    }

	  reloc_class = strtoul (buffer + len, &symname, 16);
	  if (buffer + len == symname || (reloc_class == 0 && type)
	      || (*symname != ' ' && *symname != '\t'))
	    {
	      error (0, 0, "%s: Could not parse `%s'", info->ent->filename, buffer);
	      goto error_out;
	    }

	  if (type)
	    reloc_class = dso->arch->reloc_class (reloc_class);
	  else
	    reloc_class |= RTYPE_CLASS_VALID;

	  while (*symname == ' ' || *symname == '\t') ++symname;

	  if (symstart != deps[0].start)
	    continue;

	  /* Only interested in relocations from the current object.  */
	  if (symoff < info->symtab_start || symoff >= info->symtab_end)
	    {
	      error (0, 0, "%s: Symbol `%s' offset 0x%08llx does not point into .dynsym section",
		     info->ent->filename, symname, symoff);
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
	  if (s->reloc_class)
	    {
	      while (s->reloc_class != reloc_class && s->next != NULL)
		s = s->next;
	      if (s->reloc_class == reloc_class)
		{
		  if (s->ent != ent || s->value != value[0])
		    {
		      error (0, 0, "%s: Symbol `%s' with the same reloc type resolves to different values each time",
			     info->ent->filename, symname);
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
	      s->reloc_class = reloc_class;
	      s->next = NULL;
	    }
	}
      else if (strncmp (buffer, "conflict ", sizeof ("conflict ") - 1) == 0)
	{
	  if (sscanf (buffer, "conflict 0x%llx 0x%llx -> 0x%llx 0x%llx x 0x%llx 0x%llx %n",
		      &symstart, &symoff, &valstart[0], &value[0],
		      &valstart[1], &value[1], &len) != 6)
	    {
	      error (0, 0, "%s: Could not parse `%s'", info->ent->filename, buffer);
	      goto error_out;
	    }

	  if (buffer[len] == '/')
	    {
	      ++len;
	      type = 0;
	    }

	  reloc_class = strtoul (buffer + len, &symname, 16);
	  if (buffer + len == symname || (reloc_class == 0 && type)
	      || (*symname != ' ' && *symname != '\t'))
	    {
	      error (0, 0, "%s: Could not parse `%s'", info->ent->filename, buffer);
	      goto error_out;
	    }

	  if (type)
	    reloc_class = dso->arch->reloc_class (reloc_class);
	  else
	    reloc_class |= RTYPE_CLASS_VALID;

	  while (*symname == ' ' || *symname == '\t') ++symname;

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
		  ents[j] = NULL;
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
		    && conflict->reloc_class == reloc_class)
		  {
		    if (conflict->lookupent != ents[0]
			|| conflict->conflictent != ents[1]
			|| conflict->lookupval != value[0]
			|| conflict->conflictval != value[1])
		      {
			error (0, 0, "%s: Symbol `%s' with the same reloc type resolves to different values each time",
			       info->ent->filename, symname);
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
		  conflict->reloc_class = reloc_class;
		  conflict->used = 0;
		}
	    }
	}
      else if (strncmp (buffer, "undefined symbol: ",
			sizeof ("undefined symbol: ") - 1) == 0 && ! undef)
	{
	  undef = 1;
	  if (verbose)
	    error (0, 0, "Warning: %s has undefined non-weak symbols",
		   info->ent->filename);
	}
    } while (fgets (buffer, 8192, f) != NULL);

  info->sonames = malloc (ndeps * sizeof (const char *));
  for (i = 0; i < ndeps; i++)
    info->sonames[i] = deps[i].soname;

  return 0;

error_out:
  for (i = 0; i < ndeps; i++)
    free (deps[i].soname);
  return 1;
}

int
prelink_get_relocations (struct prelink_info *info)
{
  FILE *f;
  DSO *dso = info->dso;
  const char *argv[5];
  const char *envp[4];
  int i, ret, status;
  char *p;

  info->ent->base = dso->base;
  info->ent->end = dso->end;

  if (is_ldso_soname (info->dso->soname))
    return 1;

  info->symbol_count = (info->symtab_end - info->symtab_start)
		       / info->symtab_entsize;
  info->symbols = calloc (sizeof (struct prelink_symbol), info->symbol_count);

  i = 0;
  argv[i++] = dynamic_linker;
  if (ld_library_path)
    {
      argv[i++] = "--library-path";
      argv[i++] = ld_library_path;
    }
  argv[i++] = info->ent->filename;
  argv[i] = NULL;
  envp[0] = "LD_TRACE_LOADED_OBJECTS=1";
  envp[1] = "LD_BIND_NOW=1";
  p = alloca (sizeof "LD_TRACE_PRELINKING=" + strlen (info->ent->filename));
  strcpy (stpcpy (p, "LD_TRACE_PRELINKING="), info->ent->filename);
  envp[2] = p;
  envp[3] = NULL;

  ret = 2;
  f = execve_open (dynamic_linker, (char * const *)argv, (char * const *)envp);
  if (f == NULL)
    {
      error (0, errno, "%s: Could not trace symbol resolving",
	     info->ent->filename);
      return 0;
    }

  if (prelink_record_relocations (info, f))
    ret = 0;

  if ((status = execve_close (f)))
    {
      if (ret)
	error (0, status == -1 ? errno : 0,
	       "%s Could not trace symbol resolving", info->ent->filename);
      return 0;
    }

  return ret;
}
