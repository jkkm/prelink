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

struct find_cxx_sym
{
  DSO *dso;
  int n;
  struct prelink_entry *ent;
  Elf_Data *symtab, *strtab;
  int symsec, strsec;
  GElf_Sym sym;
};

static int
find_cxx_sym (struct prelink_info *info, GElf_Addr addr,
	      struct find_cxx_sym *fcs, int reloc_size)
{
  int n, ndeps = info->ent->ndepends + 1;
  int ndx, maxndx;
  DSO *dso;
  Elf_Scn *scn;

  if (fcs->ent == NULL
      || addr < fcs->ent->base
      || addr >= fcs->ent->end)
    {
      for (n = 1; n < ndeps; ++n)
	{
	  fcs->ent = info->ent->depends[n - 1];
	  if (addr >= fcs->ent->base
	      && addr < fcs->ent->end)
	    break;
	}

      if (n == ndeps
	  && addr >= info->dso->base
	  && addr < info->dso->end)
	{
	  n = 0;
	  fcs->ent = info->ent;
	}

      assert (n < ndeps);
      fcs->n = n;
      fcs->dso = dso = info->dsos[n];
      fcs->symsec = addr_to_sec (dso, dso->info[DT_SYMTAB]);
      if (fcs->symsec == -1)
	{
	  fcs->ent = NULL;
	  return -1;
	}
      scn = elf_getscn (dso->elf, fcs->symsec);
      fcs->symtab = elf_getdata (scn, NULL);
      assert (elf_getdata (scn, fcs->symtab) == NULL);
      fcs->strsec = addr_to_sec (dso, dso->info[DT_STRTAB]);
      if (fcs->strsec == -1)
	{
	  fcs->ent = NULL;
	  return -1;
	}
      scn = elf_getscn (dso->elf, fcs->strsec);
      fcs->strtab = elf_getdata (scn, NULL);
      assert (elf_getdata (scn, fcs->strtab) == NULL);
    }
  else
    dso = fcs->dso;

  maxndx = fcs->symtab->d_size / dso->shdr[fcs->symsec].sh_entsize;
  for (ndx = 0; ndx < maxndx; ++ndx)
    {
      gelfx_getsym (dso->elf, fcs->symtab, ndx, &fcs->sym);
      if (fcs->sym.st_value <= addr
	  && fcs->sym.st_value + fcs->sym.st_size >=
	     addr + reloc_size)
	break;
    }

  if (ndx == maxndx)
    return -1;

  return ndx;
}

/* The idea here is that C++ virtual tables are always emitted
   in .gnu.linkonce.d.* sections as WEAK symbols and they
   need to be the same.
   We check if they are and if yes, remove conflicts against
   virtual tables which will not be used.  */

int
remove_redundant_cxx_conflicts (struct prelink_info *info)
{
  int i, j, k, n, o, state, removed = 0;
  int ndx, maxndx, sec;
  int reloc_type, reloc_size;
  struct find_cxx_sym fcs1, fcs2;
  char *mem1, *mem2;
  const char *name = NULL, *secname = NULL;
  GElf_Addr symtab_start;
  GElf_Word symoff;
  struct prelink_conflict *conflict;
  static struct
    {
      unsigned char *prefix;
      unsigned char prefix_len, st_info;
      unsigned char *section;
    }
  specials[] =
    {
      /* G++ 3.0 ABI.  */
      /* Virtual table.  */
      { "_ZTV", 4, GELF_ST_INFO (STB_WEAK, STT_OBJECT), ".data" },
      /* Typeinfo.  */
      { "_ZTI", 4, GELF_ST_INFO (STB_WEAK, STT_OBJECT), ".data" },
      /* G++ 2.96-RH ABI.  */
      /* Virtual table.  */
      { "__vt_", 5, GELF_ST_INFO (STB_WEAK, STT_OBJECT), ".data" },
      { NULL, 0, 0, NULL }
    };

  /* Don't bother doing this for non-C++ programs.  */
  for (i = 0; i < info->ent->ndepends; ++i)
    if (strstr (info->ent->depends[i]->canon_filename, "libstdc++"))
      break;
  if (i == info->ent->ndepends)
    return 0;

  state = 0;
  memset (&fcs1, 0, sizeof (fcs1));
  memset (&fcs2, 0, sizeof (fcs2));
  for (i = 0; i < info->conflict_rela_size; ++i)
    {
      reloc_type = GELF_R_TYPE (info->conflict_rela[i].r_info);
      reloc_size = info->dso->arch->reloc_size (reloc_type);

      if (GELF_R_SYM (info->conflict_rela[i].r_info) != 0)
	continue;

      if (state
	  && fcs1.sym.st_value <= info->conflict_rela[i].r_offset
	  && fcs1.sym.st_value + fcs1.sym.st_size
	     >= info->conflict_rela[i].r_offset + reloc_size)
	{
	  if (state == 2)
	    {
	      if (verbose > 3)
		error (0, 0, "Removing C++ conflict at %s:%s+%d",
		       fcs1.dso->filename, name,
		       (int) (info->conflict_rela[i].r_offset
			      - fcs1.sym.st_value));
	      info->conflict_rela[i].r_info =
		GELF_R_INFO (1, GELF_R_TYPE (info->conflict_rela[i].r_info));
	      ++removed;
	    }
	  continue;
	}

      n = find_cxx_sym (info, info->conflict_rela[i].r_offset,
			&fcs1, reloc_size);

      name = (const char *) fcs1.strtab->d_buf + fcs1.sym.st_name;
      state = 0;
      if (n == -1)
	continue;
      state = 1;
      sec = addr_to_sec (fcs1.dso, fcs1.sym.st_value);
      if (sec == -1)
	continue;
      secname = strptr (fcs1.dso, fcs1.dso->ehdr.e_shstrndx,
			fcs1.dso->shdr[sec].sh_name);
      if (secname == NULL)
	continue;

      for (k = 0; specials[k].prefix; ++k)
	if (GELF_ST_VISIBILITY (fcs1.sym.st_other) == STV_DEFAULT
	    && fcs1.sym.st_info == specials[k].st_info
	    && strncmp (name, specials[k].prefix, specials[k].prefix_len) == 0
	    && strcmp (secname, specials[k].section) == 0)
	  break;

      if (specials[k].prefix == NULL)
	continue;

      /* Now check there are no other symbols pointing to it.  */
      maxndx = fcs1.symtab->d_size / fcs1.dso->shdr[fcs1.symsec].sh_entsize;
      for (ndx = 0; ndx < maxndx; ++ndx)
	if (ndx != n)
	  {
	    GElf_Sym sym;

	    gelfx_getsym (fcs1.dso->elf, fcs1.symtab, ndx, &sym);
	    if ((sym.st_value + sym.st_size > fcs1.sym.st_value
		 && sym.st_value < fcs1.sym.st_value + fcs1.sym.st_size)
		|| sym.st_value == fcs1.sym.st_value)
	      break;
	  }

      if (ndx < maxndx)
	continue;

      symtab_start = fcs1.dso->shdr[fcs1.symsec].sh_addr - fcs1.dso->base;
      symoff = symtab_start + n * fcs1.dso->shdr[fcs1.symsec].sh_entsize;

      for (conflict = info->conflicts[fcs1.n]; conflict;
	   conflict = conflict->next)
	if (conflict->symoff == symoff
	    && conflict->reloc_class == RTYPE_CLASS_VALID)
	  break;

      if (conflict == NULL)
	continue;

      if (conflict->conflictent != fcs1.ent
	  || fcs1.dso->base + conflict->conflictval != fcs1.sym.st_value)
	continue;

      if (verbose > 4)
	error (0, 0, "Possible C++ conflict removal at %s:%s+%d",
	       fcs1.dso->filename, name,
	       (int) (info->conflict_rela[i].r_offset - fcs1.sym.st_value));

      /* Limit size slightly.  */
      if (fcs1.sym.st_size > 16384)
	continue;

      o = find_cxx_sym (info, conflict->lookupent->base + conflict->lookupval,
			&fcs2, fcs1.sym.st_size);

      if (o == -1
	  || fcs1.sym.st_size != fcs2.sym.st_size
	  || fcs1.sym.st_info != fcs2.sym.st_info
	  || GELF_ST_VISIBILITY (fcs2.sym.st_other) != STV_DEFAULT
	  || strcmp (name, (char *) fcs2.strtab->d_buf + fcs2.sym.st_name) != 0)
	continue;

      mem1 = malloc (fcs1.sym.st_size * 2);
      if (mem1 == NULL)
	{
	  error (0, ENOMEM, "%s: Could not compare %s arrays",
		 info->dso->filename, name);
	  return 1;
	}

      mem2 = mem1 + fcs1.sym.st_size;

      if (get_relocated_mem (info, fcs1.dso, fcs1.sym.st_value, mem1,
			     fcs1.sym.st_size)
	  || get_relocated_mem (info, fcs2.dso, fcs2.sym.st_value, mem2,
				fcs1.sym.st_size)
	  || memcmp (mem1, mem2, fcs1.sym.st_size) != 0)
	{
	  free (mem1);
	  continue;
	}

      free (mem1);

      state = 2;

      if (verbose > 3)
	error (0, 0, "Removing C++ conflict at %s:%s+%d",
	       fcs1.dso->filename, name,
	       (int) (info->conflict_rela[i].r_offset - fcs1.sym.st_value));

      info->conflict_rela[i].r_info =
	GELF_R_INFO (1, GELF_R_TYPE (info->conflict_rela[i].r_info));
      ++removed;
    }

  if (removed)
    {
      for (i = 0, j = 0; i < info->conflict_rela_size; ++i)
	if (GELF_R_SYM (info->conflict_rela[i].r_info) == 0)
	  {
	    if (i != j)
	      info->conflict_rela[j] = info->conflict_rela[i];
	    ++j;
	  }
      info->conflict_rela_size = j;
    }

  return 0;
}
