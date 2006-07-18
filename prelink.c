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
#include "prelink.h"
#include "reloc.h"

static GElf_Addr
prelink_ldso (struct prelink_info *info, GElf_Word r_sym,
	      int reloc_type __attribute__((unused)))
{
  /* Dynamic linker does not depend on any other library,
     all symbols resolve to themselves with the exception
     of SHN_UNDEF symbols which resolve to 0.  */
  if (info->symtab[r_sym].st_shndx == SHN_UNDEF)
    return 0;
  else
    /* As the dynamic linker is relocated first,
       l_addr will be 0.  */
    return 0 + info->symtab[r_sym].st_value;
}

static GElf_Addr
prelink_dso (struct prelink_info *info, GElf_Word r_sym,
	     int reloc_type)
{
  struct prelink_symbol *s;

  for (s = & info->symbols[r_sym]; s; s = s->next)
    if (s->reloc_type == reloc_type)
      break;

  if (s == NULL || s->ent == NULL)
    return 0;

  return s->ent->base + s->value;
}

static int
prelink_rel (DSO *dso, int n, struct prelink_info *info)
{
  Elf_Data *data = NULL;
  Elf_Scn *scn = elf_getscn (dso->elf, n);
  GElf_Rel rel;
  int sec;

  while ((data = elf_getdata (scn, data)) != NULL)
    {
      int ndx, maxndx;

      maxndx = data->d_size / dso->shdr[n].sh_entsize;
      for (ndx = 0; ndx < maxndx; ++ndx)
	{
	  gelfx_getrel (dso->elf, data, ndx, &rel);
	  sec = addr_to_sec (dso, rel.r_offset);
	  if (sec == -1)
	    continue;

	  if (dso->arch->prelink_rel (info, &rel))
	    return 1;
	}
    }
  return 0;
}

static int
prelink_rela (DSO *dso, int n, struct prelink_info *info)
{
  Elf_Data *data = NULL;
  Elf_Scn *scn = elf_getscn (dso->elf, n);
  GElf_Rela rela;
  int sec;

  while ((data = elf_getdata (scn, data)) != NULL)
    {
      int ndx, maxndx;

      maxndx = data->d_size / dso->shdr[n].sh_entsize;
      for (ndx = 0; ndx < maxndx; ++ndx)
	{
	  gelfx_getrela (dso->elf, data, ndx, &rela);
	  sec = addr_to_sec (dso, rela.r_offset);
	  if (sec == -1)
	    continue;

	  if (dso->arch->prelink_rela (info, &rela))
	    return 1;
	}
    }
  return 0;
}

int
prelink_prepare (DSO *dso)
{
  struct reloc_info rinfo;
  int i;
  
  if (dso->ehdr.e_type != ET_DYN)
    return 0;

  /* At least on i386 the dynamic linker can stay with REL,
     since R_386_32 and R_386_PC32 relocs are not present,
     so it is possible to relocate it multiple times
     (assuming l_addr == 0).  */
  if (! strcmp (dso->soname, ldso_soname))
    return 0;

  if (find_reloc_sections (dso, &rinfo))
    return 1;

  if (! rinfo.gnureloc && ! rinfo.rel_to_rela && ! rinfo.rel_to_rela_plt)
    return 0;

  if (rinfo.first && ! rinfo.gnureloc)
    {
      Elf_Data data, *d;
      GElf_Shdr shdr;
      struct section_move *move;

      move = init_section_move (dso);
      if (move == NULL)
	return 1;

      if (build_gnu_reloc (dso, &data, rinfo.first, rinfo.last))
	{
	  free (move);
	  return 1;
	}

      for (i = rinfo.last; i >= rinfo.first + 1; i--)
	remove_section (move, i);
      shdr = dso->shdr[rinfo.first];
      shdr.sh_info = 0;
      shdr.sh_size = data.d_size;

      if (reopen_dso (dso, move))
	{
	  free (data.d_buf);
	  free (move);
	  return 1;
	}

      free (move);
      dso->shdr[rinfo.first] = shdr;
      d = elf_getdata (elf_getscn (dso->elf, rinfo.first), NULL);
      free (d->d_buf);
      memcpy (d, &data, sizeof (data));
      if (rinfo.plt)
	rinfo.plt -= rinfo.last - rinfo.first;
      rinfo.last = rinfo.first;
      dso->shdr[rinfo.first].sh_name = shstrtabadd (dso, ".gnu.reloc");
      if (dso->shdr[rinfo.first].sh_name == 0)
	return 1;
    }
  else if (reopen_dso (dso, NULL))
    return 1;

  if (rinfo.rel_to_rela || rinfo.rel_to_rela_plt)
    {
      /* On REL architectures, we might need to convert some REL
	 relocations to RELA relocs.  */

      int safe = 1, align = 0;
      GElf_Addr start, adjust, adjust1, adjust2;

      for (i = 1; i < (rinfo.plt ? rinfo.plt : rinfo.first); i++)
	switch (dso->shdr[i].sh_type)
	  {
	  case SHT_HASH:
	  case SHT_DYNSYM:
	  case SHT_REL:
	  case SHT_RELA:
	  case SHT_STRTAB:
	  case SHT_NOTE:
	  case SHT_GNU_verdef:
	  case SHT_GNU_verneed:
	  case SHT_GNU_versym:
	    /* These sections are safe, no relocations should point
	       to it, therefore enlarging a section after sections
	       from this set only (and SHT_REL) in ET_DYN just needs
	       adjusting the rest of the library.  */
	    break;
	  default:
	    /* The rest of sections are not safe.  */
	    safe = 0;
	    break;
	  }

      if (! safe)
	{
	  error (0, 0, "%s: Cannot safely convert %s' section from REL to RELA",
		 dso->filename, strptr (dso, dso->ehdr.e_shstrndx,
					dso->shdr[rinfo.rel_to_rela
					? rinfo.first : rinfo.plt].sh_name));
	  return 1;
	}
                                                             
      for (i = rinfo.plt ? rinfo.plt : rinfo.first; i < dso->ehdr.e_shnum; i++)
	{
	  if (dso->shdr[i].sh_addralign > align)
	    align = dso->shdr[i].sh_addralign;
	}

      if (rinfo.plt)
	start = dso->shdr[rinfo.plt].sh_addr + dso->shdr[rinfo.plt].sh_size;
      else
	start = dso->shdr[rinfo.first].sh_addr + dso->shdr[rinfo.first].sh_size;

      adjust1 = 0;
      adjust2 = 0;
      assert (sizeof (Elf32_Rel) * 3 == sizeof (Elf32_Rela) * 2);
      assert (sizeof (Elf64_Rel) * 3 == sizeof (Elf64_Rela) * 2);
      if (rinfo.rel_to_rela)
	{
	  GElf_Addr size = dso->shdr[rinfo.first].sh_size / 2 * 3;
	  adjust1 = size - dso->shdr[rinfo.first].sh_size;
	  if (convert_rel_to_rela (dso, rinfo.first))
	    return 1;
	}
      if (rinfo.rel_to_rela_plt)
	{
	  GElf_Addr size = dso->shdr[rinfo.plt].sh_size / 2 * 3;
	  adjust2 = size - dso->shdr[rinfo.plt].sh_size;
	  if (convert_rel_to_rela (dso, rinfo.plt))
	    return 1;
	}

      adjust = adjust1 + adjust2;

      /* Need to make sure that all the remaining sections are properly
	 aligned.  */
      if (align)
	adjust = (adjust + align - 1) & ~(align - 1);

      /* Adjust all addresses pointing into remaining sections.  */
      if (adjust_dso (dso, start, adjust))
	return 1;

      if (rinfo.rel_to_rela)
	{
	  dso->shdr[rinfo.first].sh_size += adjust1;
	  if (rinfo.plt)
	    {
	      dso->shdr[rinfo.plt].sh_addr += adjust1;
	      dso->shdr[rinfo.plt].sh_offset += adjust1;
	    }
	}
      if (rinfo.rel_to_rela_plt)
	dso->shdr[rinfo.plt].sh_size += adjust2;

      if (update_dynamic_rel (dso, &rinfo))
	return 1;
    }

  return 0;
}

int
prelink (DSO *dso)
{
  int i;
  Elf_Scn *scn;
  Elf_Data *data;
  struct prelink_info info;

  if (! dso->info[DT_SYMTAB])
    return 0;

  if (! dso_is_rdwr (dso) && dso->ehdr.e_type == ET_DYN)
    {
      if (reopen_dso (dso, NULL))
	return 1;
    }
                        
  i = addr_to_sec (dso, dso->info[DT_SYMTAB]);
  /* DT_SYMTAB should be found and should point to
     start of .dynsym section.  */
  if (i == -1
      || dso->info[DT_SYMTAB] != dso->shdr[i].sh_addr)
    {
      error (0, 0, "%s: Bad symtab", dso->filename);
      return 1;
    }

  memset (&info, 0, sizeof (info));
  info.symtab_entsize = dso->shdr[i].sh_entsize;
  info.symtab = calloc (dso->shdr[i].sh_size / dso->shdr[i].sh_entsize,
			sizeof (GElf_Sym));
  if (info.symtab == NULL)
    {
      error (0, ENOMEM, "%s: Cannot convert .dynsym section", dso->filename);
      return 1;
    }

  scn = elf_getscn (dso->elf, i);
  data = NULL;
  while ((data = elf_getdata (scn, data)) != NULL)
    {
      int ndx, maxndx, loc;

      loc = data->d_off / info.symtab_entsize;
      maxndx = data->d_size / info.symtab_entsize;
      for (ndx = 0; ndx < maxndx; ++ndx)
	gelfx_getsym (dso->elf, data, ndx, info.symtab + loc + ndx);
    }
  info.symtab_start =
    adjust_new_to_old (dso, dso->shdr[i].sh_addr - dso->base);
  info.symtab_end = info.symtab_start + dso->shdr[i].sh_size;
  info.dso = dso;
  switch (prelink_get_relocations (&info))
    {
    case 0:
      goto error_out;
    case 1:
      info.resolve = prelink_ldso;
      break;
    case 2:
      info.resolve = prelink_dso;
      break;
    }

  if (dso->ehdr.e_type == ET_EXEC)
    if (prelink_exec (&info))
      goto error_out;

  for (i = 1; i < dso->ehdr.e_shnum; i++)
    {
      if (! (dso->shdr[i].sh_flags & SHF_ALLOC))
	continue;
      if (! strcmp (strptr (dso, dso->ehdr.e_shstrndx,
			    dso->shdr[i].sh_name),
		    ".gnu.conflict"))
	continue;
      switch (dso->shdr[i].sh_type)
	{
	case SHT_REL:
	  if (prelink_rel (dso, i, &info))
	    goto error_out;
	  break;
	case SHT_RELA:
	  if (prelink_rela (dso, i, &info))
	    goto error_out;
	  break;
	}
    }

  if (dso->arch->arch_prelink && dso->arch->arch_prelink (dso))
    goto error_out;

  free (info.symtab);
  return 0;

error_out:
  free (info.symtab);
  return 1;
}
