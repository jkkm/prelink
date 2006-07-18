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
#include <endian.h>
#include <errno.h>
#include <error.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include "prelink.h"
#include "reloc.h"

int
prelink_undo (DSO *dso)
{
  GElf_Shdr *shdr;
  int undo, shnum, i, j, k;
  int reldyn_first = 0, reldyn_last = 0;
  int rel_to_rela = 0, rel_to_rela_plt = 0;
  Elf_Data src, dst, *d;
  Elf_Scn *scn;
  struct section_move *move;
  const char *p;

  for (undo = 1; undo < dso->ehdr.e_shnum; ++undo)
    if (! strcmp (strptr (dso, dso->ehdr.e_shstrndx, dso->shdr[undo].sh_name),
		  ".gnu.prelink_undo"))
      break;

  if (undo == dso->ehdr.e_shnum)
    {
      error (0, 0, "%s does not have .gnu.prelink_undo section", dso->filename);
      return 1;
    }

  shnum = dso->shdr[undo].sh_size / dso->shdr[undo].sh_entsize + 1;
  shdr = alloca (sizeof (GElf_Shdr) * shnum);
  memset (shdr, 0, sizeof (GElf_Shdr));
  scn = elf_getscn (dso->elf, undo);
  d = elf_getdata (scn, NULL);
  assert (d != NULL && elf_getdata (scn, d) == NULL);
  src = *d;
  src.d_type = ELF_T_SHDR;
  src.d_align = dso->shdr[undo].sh_addralign;
  dst = src;
  switch (gelf_getclass (dso->elf))
    {
    case ELFCLASS32:
      dst.d_buf = alloca (dst.d_size);
      break;
    case ELFCLASS64:
      dst.d_buf = shdr + 1;
      break;
    default:
      return 1;
    }
  if (gelf_xlatetom (dso->elf, &dst, &src, dso->ehdr.e_ident[EI_DATA]) == NULL)
    {
      error (0, 0, "%s: Could not read .gnu.prelink_undo section",
	     dso->filename);
      return 1;
    }

  if (gelf_getclass (dso->elf) == ELFCLASS32)
    {
      Elf32_Shdr *shdr32 = (Elf32_Shdr *) dst.d_buf;

      for (i = 1; i < shnum; ++i)
	{
#define COPY(name) shdr[i].name = shdr32[i - 1].name
	  COPY (sh_name);
	  COPY (sh_type);
	  COPY (sh_flags);
	  COPY (sh_addr);
	  COPY (sh_offset);
	  COPY (sh_size);
	  COPY (sh_link);
	  COPY (sh_info);
	  COPY (sh_addralign);
	  COPY (sh_entsize);
	}
    }

  move = init_section_move (dso);
  move->new_shnum = shnum;
  for (i = 1; i < move->old_shnum; ++i)
    move->old_to_new[i] = -1;
  for (i = 1; i < move->new_shnum; ++i)
    move->new_to_old[i] = -1;

  for (i = 1; i < move->old_shnum; ++i)
    {
      for (j = 1; j < move->new_shnum; ++j)
	if (dso->shdr[i].sh_name == shdr[j].sh_name
	    && dso->shdr[i].sh_type == shdr[j].sh_type
	    && dso->shdr[i].sh_flags == shdr[j].sh_flags
	    && dso->shdr[i].sh_addralign == shdr[j].sh_addralign
	    && dso->shdr[i].sh_entsize == shdr[j].sh_entsize
	    && dso->shdr[i].sh_size == shdr[j].sh_size
	    && move->new_to_old[j] == -1)
	  break;

      if (j == move->new_shnum)
	continue;

      move->old_to_new[i] = j;
      move->new_to_old[j] = i;
    }

  for (i = 1; i < move->old_shnum; ++i)
    if (move->old_to_new[i] == -1)
      {
	const char *name = strptr (dso, dso->ehdr.e_shstrndx,
				   dso->shdr[i].sh_name);

        if (! strcmp (name, ".gnu.prelink_undo")
	    || ! strcmp (name, ".gnu.conflict")
	    || ! strcmp (name, ".gnu.liblist")
	    || ! strcmp (name, ".gnu.libstr")
	    || ((! strcmp (name, ".dynbss") || ! strcmp (name, ".sdynbss"))
		&& dso->ehdr.e_type == ET_EXEC))
	  continue;

	if ((! strcmp (name, ".dynstr") && dso->ehdr.e_type == ET_EXEC)
	    || i == dso->ehdr.e_shstrndx)
	  {
	    for (j = 1; j < move->new_shnum; ++j)
	      if (dso->shdr[i].sh_name == shdr[j].sh_name
		  && dso->shdr[i].sh_type == shdr[j].sh_type
		  && dso->shdr[i].sh_flags == shdr[j].sh_flags
		  && dso->shdr[i].sh_addralign == shdr[j].sh_addralign
		  && dso->shdr[i].sh_entsize == shdr[j].sh_entsize
		  && dso->shdr[i].sh_size > shdr[j].sh_size
		  && move->new_to_old[j] == -1)
		break;

	    if (j < move->new_shnum)
	      {
		move->old_to_new[i] = j;
		move->new_to_old[j] = i;
		continue;
	      }
	  }

	if (! strcmp (name, ".rel.dyn") || ! strcmp (name, ".rela.dyn"))
	  {
	    for (j = 1; j < move->new_shnum; ++j)
	      if (move->new_to_old[j] == -1
		  && (shdr[j].sh_type == SHT_REL
		      || shdr[j].sh_type == SHT_RELA)
		  && dso->shdr[i].sh_addralign == shdr[j].sh_addralign
		  && dso->shdr[i].sh_flags == shdr[j].sh_flags)
		break;
	    if (j < move->new_shnum)
	      {
		GElf_Addr size;

	        for (k = j + 1; k < move->new_shnum; ++k)
		  {
		    const char *name2;

		    if (move->new_to_old[k] != -1
			&& shdr[j].sh_type != shdr[k].sh_type
			&& shdr[j].sh_addralign != shdr[k].sh_addralign
			&& shdr[j].sh_flags != shdr[k].sh_flags)
		      break;

		    name2 = strptr (dso, dso->ehdr.e_shstrndx,
				    shdr[k].sh_name);
		    if (! strcmp (name2, ".rel.plt")
			|| ! strcmp (name2, ".rela.plt"))
		      break;
		  }
		size = shdr[k - 1].sh_addr - shdr[j].sh_addr;
		size += shdr[k - 1].sh_size;
		assert (sizeof (Elf32_Rel) * 3 == sizeof (Elf32_Rela) * 2);
		assert (sizeof (Elf64_Rel) * 3 == sizeof (Elf64_Rela) * 2);
		if (dso->shdr[i].sh_size == size
		    || (dso->shdr[i].sh_type == SHT_RELA
			&& shdr[j].sh_type == SHT_REL
			&& dso->shdr[i].sh_size * 2 == size * 3))
		  {
		    if (dso->shdr[i].sh_size > size)
		      rel_to_rela = 1;
		    move->old_to_new[i] = j;
		    move->new_to_old[j] = i;
		    reldyn_first = j;
		    reldyn_last = k - 1;
		    continue;
		  }
	      }
	  }

	error (0, 0, "%s: Section %s not created by prelink created after prelinking",
	       dso->filename, name);
	free (move);
	return 1;
      }

  for (i = 1; i < move->new_shnum; ++i)
    if (move->new_to_old[i] == -1
	&& (i <= reldyn_first || i > reldyn_last))
      {
	const char *name = strptr (dso, dso->ehdr.e_shstrndx, shdr[i].sh_name);

	error (0, 0, "%s: Section %s removed after prelinking", dso->filename,
	       name);
	free (move);
	return 1;
      }

  if (reopen_dso (dso, move))
    {
      free (move);
      return 1;
    }

  p = strptr (dso, dso->ehdr.e_shstrndx, shdr[reldyn_first].sh_name);
  if (reldyn_last > reldyn_first
      || (strcmp (p, ".rel.dyn") && strcmp (p, ".rela.dyn")))
    {
    }

  free (move);      
  return 0;
}
