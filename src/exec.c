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

#include <config.h>
#include <assert.h>
#include <errno.h>
#include <error.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include "prelink.h"
#include "reloc.h"
#include "space.h"

int
update_dynamic_tags (DSO *dso, GElf_Shdr *shdr, GElf_Shdr *old_shdr,
		     struct section_move *move)
{
  int i, j;
  
  for (i = 1; i < move->new_shnum; ++i)
    {
      j = move->new_to_old[i];
      if (j == -1)
	continue;
      if ((dynamic_info_is_set (dso, DT_HASH)
	   && dso->info[DT_HASH] == old_shdr[j].sh_addr
	   && old_shdr[j].sh_type == SHT_HASH
	   && set_dynamic (dso, DT_HASH, shdr[i].sh_addr, 1))
	  || (dynamic_info_is_set (dso, DT_SYMTAB)
	      && dso->info[DT_SYMTAB] == old_shdr[j].sh_addr
	      && old_shdr[j].sh_type == SHT_DYNSYM
	      && set_dynamic (dso, DT_SYMTAB, shdr[i].sh_addr, 1))
	  || (dynamic_info_is_set (dso, DT_STRTAB)
	      && dso->info[DT_STRTAB] == old_shdr[j].sh_addr
	      && old_shdr[j].sh_type == SHT_STRTAB
	      && set_dynamic (dso, DT_STRTAB, shdr[i].sh_addr, 1))
	  || (dynamic_info_is_set (dso, DT_VERDEF_BIT)
	      && dso->info_DT_VERDEF == old_shdr[j].sh_addr
	      && old_shdr[j].sh_type == SHT_GNU_verdef
	      && set_dynamic (dso, DT_VERDEF, shdr[i].sh_addr, 1))
	  || (dynamic_info_is_set (dso, DT_VERNEED_BIT)
	      && dso->info_DT_VERNEED == old_shdr[j].sh_addr
	      && old_shdr[j].sh_type == SHT_GNU_verneed
	      && set_dynamic (dso, DT_VERNEED, shdr[i].sh_addr, 1)) 
	  || (dynamic_info_is_set (dso, DT_VERSYM_BIT)
	      && dso->info_DT_VERSYM == old_shdr[j].sh_addr
	      && old_shdr[j].sh_type == SHT_GNU_versym
	      && set_dynamic (dso, DT_VERSYM, shdr[i].sh_addr, 1)))
	return 1;
    }

  return 0;
}

int
prelink_exec (struct prelink_info *info)
{
  int i, j, ndeps = info->ent->ndepends + 1;
  int dynstrndx, growdynstr = 0;
  int old_conflict = 0, old_liblist = 0;
  int new_conflict = -1, new_liblist = -1;
  int new_reloc = -1, new_plt = -1, new_dynstr = -1;
  int old_dynbss = -1, old_bss = -1, new_dynbss = -1;
  int old_sdynbss = -1, old_sbss = -1, new_sdynbss = -1;
  int *old, *new;
  int addcnt, undo = 0;
  struct reloc_info rinfo;
  DSO *dso = info->dso;
  GElf_Ehdr ehdr;
  GElf_Phdr phdr[dso->ehdr.e_phnum + 1];
  GElf_Shdr old_shdr[dso->ehdr.e_shnum], new_shdr[dso->ehdr.e_shnum + 20];
  GElf_Shdr *shdr, *add;
  Elf32_Lib *liblist = NULL;
  struct readonly_adjust adjust;
  struct section_move *move = NULL;

  if (prelink_build_conflicts (info))
    return 1;

  if (find_reloc_sections (dso, &rinfo))
    return 1;

  move = init_section_move (dso);
  if (move == NULL)
    return 1;

  for (dynstrndx = 1; dynstrndx < dso->ehdr.e_shnum; ++dynstrndx)
    if (! strcmp (strptr (dso, dso->ehdr.e_shstrndx,
			  dso->shdr[dynstrndx].sh_name),
		  ".dynstr"))
      break;

  if (dynstrndx == dso->ehdr.e_shnum)
    {
      error (0, 0, "%s: Could not find .dynstr section", dso->filename);
      goto error_out;
    }

  liblist = calloc (ndeps - 1, sizeof (Elf32_Lib));
  if (liblist == NULL)
    {
      error (0, ENOMEM, "%s: Cannot build .gnu.liblist section",
	     dso->filename);
      goto error_out;
    }

  for (i = 0; i < ndeps - 1; ++i)
    {
      struct prelink_entry *ent = info->ent->depends[i];

      liblist[i].l_name = strtabfind (dso, dynstrndx, info->sonames[i + 1]);
      if (liblist[i].l_name == 0)
	growdynstr += strlen (info->sonames[i + 1]) + 1;
      liblist[i].l_time_stamp = ent->timestamp;
      liblist[i].l_checksum = ent->checksum;
    }

  /* Find where to create .gnu.liblist and .gnu.conflict.  */
  ehdr = dso->ehdr;
  memcpy (phdr, dso->phdr, dso->ehdr.e_phnum * sizeof (GElf_Phdr));
  memcpy (old_shdr, dso->shdr, dso->ehdr.e_shnum * sizeof (GElf_Shdr));
  shdr = new_shdr;
  shdr[0] = dso->shdr[0];
  if (info->dynbss)
    {
      old_bss = addr_to_sec (dso, info->dynbss_base);
      assert (old_bss != -1);
    }
  if (info->sdynbss)
    {
      old_sbss = addr_to_sec (dso, info->sdynbss_base);
      assert (old_sbss != -1);
    }
  for (i = 1, j = 1; i < dso->ehdr.e_shnum; ++i)
    {
      const char *name = strptr (dso, dso->ehdr.e_shstrndx,
				 dso->shdr[i].sh_name);
      if (! strcmp (name, ".dynbss"))
	old_dynbss = i;
      else if (! strcmp (name, ".sdynbss"))
	old_sdynbss = i;
      else if (! strcmp (name, ".gnu.prelink_undo"))
	undo = -1;
      if (! strcmp (name, ".gnu.conflict"))
	{
	  old_conflict = i;
	  remove_section (move, move->old_to_new[i]);
	}
      else if (! strcmp (name, ".gnu.liblist"))
	{
	  old_liblist = i;
	  remove_section (move, move->old_to_new[i]);
	}
      else if (rinfo.rel_to_rela && i >= rinfo.first && i <= rinfo.last)
	remove_section (move, move->old_to_new[i]);
      else if (i == rinfo.plt
	       && (rinfo.rel_to_rela || rinfo.rel_to_rela_plt))
	remove_section (move, move->old_to_new[i]);
      else if (i == dynstrndx && growdynstr)
	remove_section (move, move->old_to_new[i]);
      else
	shdr[j++] = dso->shdr[i];
    }
  assert (j == move->new_shnum);
  ehdr.e_shnum = j;

  add = alloca ((rinfo.last - rinfo.first + 5) * sizeof (*add));
  old = alloca ((rinfo.last - rinfo.first + 5) * sizeof (*old));
  new = alloca ((rinfo.last - rinfo.first + 5) * sizeof (*new));
  memset (add, 0, (rinfo.last - rinfo.first + 5) * sizeof (*add));
  memset (old, 0, (rinfo.last - rinfo.first + 5) * sizeof (*old));
  memset (new, 0, (rinfo.last - rinfo.first + 5) * sizeof (*new));

  i = 0;
  if (rinfo.rel_to_rela)
    {
      add[i] = dso->shdr[rinfo.first];
      add[i].sh_size = dso->shdr[rinfo.last].sh_addr
		       + dso->shdr[rinfo.last].sh_size - add[i].sh_addr;
      assert (sizeof (Elf32_Rel) * 3 == sizeof (Elf32_Rela) * 2);
      assert (sizeof (Elf64_Rel) * 3 == sizeof (Elf64_Rela) * 2);
      add[i].sh_size = add[i].sh_size / 2 * 3;
      old[i] = rinfo.first;
      new_reloc = i++;
      for (j = rinfo.first + 1; j <= rinfo.last; ++j)
	{
	  add[i] = dso->shdr[j];
	  add[i].sh_size = add[i].sh_size / 2 * 3;
	  old[i++] = j;
	}
      if (rinfo.plt)
	{
	  add[i] = dso->shdr[rinfo.plt];
	  if (rinfo.rel_to_rela_plt)
	    add[i].sh_size = add[i].sh_size / 2 * 3;
	  /* Temporarily merge them, so that they are allocated adjacently.  */
	  add[new_reloc].sh_size += add[i].sh_size;
	  old[i] = rinfo.plt;
	  new_plt = i++;
	}
    }
  else if (rinfo.rel_to_rela_plt)
    {
      add[i] = dso->shdr[rinfo.plt];
      assert (sizeof (Elf32_Rel) * 3 == sizeof (Elf32_Rela) * 2);
      assert (sizeof (Elf64_Rel) * 3 == sizeof (Elf64_Rela) * 2);
      add[i].sh_size = add[i].sh_size / 2 * 3;
      old[i] = rinfo.plt;
      new_plt = i++;
    }
  if (growdynstr)
    {
      add[i] = dso->shdr[dynstrndx];
      add[i].sh_size += growdynstr;
      old[i] = dynstrndx;
      new_dynstr = i++;
    }
  add[i].sh_flags = SHF_ALLOC;
  add[i].sh_type = SHT_GNU_LIBLIST;
  add[i].sh_size = (ndeps - 1) * sizeof (Elf32_Lib);
  add[i].sh_addralign = sizeof (GElf_Word);
  add[i].sh_entsize = sizeof (Elf32_Lib);
  old[i] = old_liblist;
  new_liblist = i++;
  if (info->conflict_rela_size)
    {
      add[i].sh_flags = SHF_ALLOC;
      add[i].sh_type = SHT_RELA;
      add[i].sh_entsize = gelf_fsize (dso->elf, ELF_T_RELA, 1, EV_CURRENT);
      add[i].sh_size = info->conflict_rela_size * add[i].sh_entsize;
      add[i].sh_addralign = gelf_fsize (dso->elf, ELF_T_ADDR, 1, EV_CURRENT);
      old[i] = old_conflict;
      new_conflict = i++;
    }
  addcnt = i;
  memset (&adjust, 0, sizeof (adjust));
  adjust.new = new;

  for (i = 0; i < addcnt; ++i)
    {
      new[i] = find_readonly_space (dso, add + i, &ehdr, phdr, shdr, &adjust);
      if (new[i] == 0)
	goto error_out;
      add_section (move, new[i]);
      ++adjust.newcount;
      if (old[i])
	{
	  move->old_to_new[old[i]] = new[i];
	  move->new_to_old[new[i]] = old[i];
	}
      if (i == new_reloc)
	{
	  int k, l = new[new_reloc];

	  j = rinfo.last - rinfo.first + (new_plt != -1);
	  shdr[l].sh_size = dso->shdr[rinfo.first].sh_size / 2 * 3;
	  for (k = 1; k <= j; ++k)
	    {
	      insert_readonly_section (&ehdr, shdr, l + k, &adjust);
	      shdr[l + k] = add[new_reloc + k];
	      shdr[l + k].sh_addr = shdr[l + k - 1].sh_addr
				    + shdr[l + k - 1].sh_size;
	      shdr[l + k].sh_offset = shdr[l + k - 1].sh_offset
				      + shdr[l + k - 1].sh_size;
	      new[++i] = l + k;
	      add_section (move, l + k);
	      move->old_to_new[rinfo.first + k] = l + k;
	      move->new_to_old[l + k] = rinfo.first + k;
	      ++adjust.newcount;
	    }
	}
    }

  if (info->sdynbss)
    {
      if (old_sdynbss == -1)
	{
	  new_sdynbss = move->old_to_new[old_sbss];
	  memmove (&shdr[new_sdynbss + 1], &shdr[new_sdynbss],
		   (ehdr.e_shnum - new_sdynbss) * sizeof (GElf_Shdr));
	  shdr[new_sdynbss].sh_size = 0;
	  ++ehdr.e_shnum;
	  add_section (move, new_sdynbss);
	  for (i = 0; i < addcnt; ++i)
	    if (new[i] >= new_sdynbss)
	      ++new[i];
	}
      else
	new_sdynbss = move->old_to_new[old_sdynbss];
    }

  if (info->dynbss)
    {
      if (old_dynbss == -1)
	{
	  new_dynbss = move->old_to_new[old_bss];
	  memmove (&shdr[new_dynbss + 1], &shdr[new_dynbss],
		   (ehdr.e_shnum - new_dynbss) * sizeof (GElf_Shdr));
	  shdr[new_dynbss].sh_size = 0;
	  ++ehdr.e_shnum;
	  add_section (move, new_dynbss);
	  for (i = 0; i < addcnt; ++i)
	    if (new[i] >= new_dynbss)
	      ++new[i];
	}
      else
	new_dynbss = move->old_to_new[old_dynbss];
    }

  if (undo != -1)
    {
      undo = move->old_to_new[dso->ehdr.e_shstrndx];
      memmove (&shdr[undo + 1], &shdr[undo],
	       (ehdr.e_shnum - undo) * sizeof (GElf_Shdr));
      memset (&shdr[undo], 0, sizeof (shdr[undo]));
      shdr[undo].sh_type = SHT_PROGBITS;
      shdr[undo].sh_addralign = dso->undo.d_align;
      ++ehdr.e_shnum;
      for (i = 0; i < addcnt; ++i)
	if (new[i] >= undo)
	  ++new[i];
      add_section (move, undo);
    }

  i = ehdr.e_shnum;
  ehdr.e_shnum = dso->ehdr.e_shnum;
  dso->ehdr = ehdr;
  memcpy (dso->phdr, phdr, ehdr.e_phnum * sizeof (GElf_Phdr));
  if (reopen_dso (dso, move))
    goto error_out;

  assert (i == dso->ehdr.e_shnum);

  if (move->old_shnum != move->new_shnum)
    adjust_nonalloc (dso, &dso->ehdr, shdr, 0,
		     dso->ehdr.e_shoff + 1,
		     ((long) move->new_shnum - (long) move->old_shnum)
		     * gelf_fsize (dso->elf, ELF_T_SHDR, 1, EV_CURRENT));

  for (i = 1; i < dso->ehdr.e_shnum; ++i)
    if (move->new_to_old[i] == -1)
      dso->shdr[i] = shdr[i];
    else
      {
	if (shdr[i].sh_type == SHT_PROGBITS
	    && dso->shdr[i].sh_type == SHT_NOBITS)
	  {
	    Elf_Data *data = elf_getdata (dso->scn[i], NULL);

	    assert (data->d_buf == NULL);
	    assert (data->d_size == shdr[i].sh_size);
	    data->d_buf = calloc (shdr[i].sh_size, 1);
	    if (data->d_buf == NULL)
	      {
		error (0, ENOMEM, "%s: Could not convert NOBITS section into PROGBITS",
		       dso->filename);
		goto error_out;
	      }
	    data->d_type = ELF_T_BYTE;
	  }
	dso->shdr[i].sh_type = shdr[i].sh_type;
	dso->shdr[i].sh_addr = shdr[i].sh_addr;
	dso->shdr[i].sh_size = shdr[i].sh_size;
	dso->shdr[i].sh_offset = shdr[i].sh_offset;
      }

  for (i = 0; i < dso->ehdr.e_phnum; ++i)
    if (dso->phdr[i].p_type == PT_LOAD)
      {
	GElf_Addr last_offset = dso->phdr[i].p_offset;
	GElf_Addr adj = 0;
	int sfirst = 0, slast = 0, last = 0;

	for (j = 1; j < dso->ehdr.e_shnum; ++j)
	  if (dso->shdr[j].sh_addr >= dso->phdr[i].p_vaddr
	      && dso->shdr[j].sh_addr + dso->shdr[j].sh_size
		 <= dso->phdr[i].p_vaddr + dso->phdr[i].p_memsz)
	    {
	      if (dso->shdr[j].sh_type != SHT_NOBITS)
		{
		  if (sfirst)
		    {
		      error (0, 0, "%s: NOBITS section followed by non-NOBITS section in the same segment",
			     dso->filename);
		      goto error_out;
		    }
		  continue;
		}

	      if (!sfirst)
		sfirst = j;
	      if (strcmp (strptr (dso, dso->ehdr.e_shstrndx,
				  dso->shdr[j].sh_name), ".plt") == 0)
		slast = j + 1;
	      else if (j == new_dynbss || j == new_sdynbss)
		slast = j;
	    }

	if (sfirst && slast)
	  {
	    for (j = sfirst; j < slast; ++j)
	      {
		Elf_Data *data = elf_getdata (dso->scn[j], NULL);

		assert (data->d_buf == NULL);
		assert (data->d_size == dso->shdr[j].sh_size);
		data->d_buf = calloc (dso->shdr[j].sh_size, 1);
		if (data->d_buf == NULL)
		  {
		    error (0, ENOMEM, "%s: Could not convert NOBITS section into PROGBITS",
			   dso->filename);
		    goto error_out;
		  }
		data->d_type = ELF_T_BYTE;
		dso->shdr[j].sh_type = SHT_PROGBITS;
	      }

	    adj = dso->shdr[slast - 1].sh_addr + dso->shdr[slast - 1].sh_size
		  - dso->phdr[i].p_vaddr;

	    if (adj > dso->phdr[i].p_filesz)
	      {
		adj -= dso->phdr[i].p_filesz;
		for (j = slast;
		     j < dso->ehdr.e_shnum
		     && (dso->shdr[j].sh_flags
			 & (SHF_WRITE | SHF_ALLOC | SHF_EXECINSTR));
		     ++j)
		  if (dso->shdr[j].sh_addr >= dso->phdr[i].p_vaddr
					      + dso->phdr[i].p_memsz)
		    adj = (adj + dso->shdr[j].sh_addralign - 1)
			  & ~(dso->shdr[j].sh_addralign - 1);

		dso->phdr[i].p_filesz += adj;
	      }
	    else
	      adj = 0;
	  }

	for (j = 1; j < dso->ehdr.e_shnum; ++j)
	  if (dso->shdr[j].sh_addr >= dso->phdr[i].p_vaddr
	      && dso->shdr[j].sh_addr + dso->shdr[j].sh_size
		 <= dso->phdr[i].p_vaddr + dso->phdr[i].p_memsz)
	    {
	      last = j;
	      if (dso->shdr[j].sh_type == SHT_NOBITS)
		{
		  last_offset += dso->shdr[j].sh_addralign - 1;
		  last_offset &= ~(dso->shdr[j].sh_addralign - 1);
		  if (last_offset > dso->phdr[i].p_offset
				    + dso->phdr[i].p_filesz)
		    last_offset = dso->phdr[i].p_offset
				  + dso->phdr[i].p_filesz;
		  dso->shdr[j].sh_offset = last_offset;
		}
	      else if (dso->shdr[j].sh_addr + dso->shdr[j].sh_size
		       > dso->phdr[i].p_vaddr + dso->phdr[i].p_filesz)
		{
		  error (0, 0, "%s: section spans beyond end of segment",
			 dso->filename);
		  goto error_out;
		}
	      else
		{
		  dso->shdr[j].sh_offset
		    = dso->phdr[i].p_offset + dso->shdr[j].sh_addr
		      - dso->phdr[i].p_vaddr;
		  last_offset = dso->shdr[j].sh_offset + dso->shdr[j].sh_size;
		}
	    }

	if (adj)
	  {
	    for (j = i + 1; j < dso->ehdr.e_phnum; ++j)
	      if (dso->phdr[j].p_type == PT_LOAD
		  && dso->phdr[j].p_vaddr >= dso->shdr[slast - 1].sh_addr)
		{
		  dso->phdr[j].p_vaddr += adj;
		  dso->phdr[j].p_paddr += adj;
		  dso->phdr[j].p_offset += adj;
		}

	    j = last + 1;
	    while (j < dso->ehdr.e_shnum
		   && (dso->shdr[j].sh_flags
		       & (SHF_WRITE | SHF_ALLOC | SHF_EXECINSTR)))
	      {
		dso->shdr[j].sh_offset += adj;
		dso->shdr[j++].sh_addr += adj;
	      }

	    if (adjust_dso_nonalloc (dso, last + 1,
				     dso->shdr[sfirst].sh_offset,
				     adj))
	      goto error_out;
	  }
      }

  /* Adjust .rel*.dyn (or .rel*.*) if necessary.  */
  assert (new_reloc == -1
	  || (rinfo.last - rinfo.first
	      == (move->old_to_new[rinfo.last]
		  - move->old_to_new[rinfo.first])));
  rinfo.first = move->old_to_new[rinfo.first];
  rinfo.last = move->old_to_new[rinfo.last];
  assert (new_reloc == -1 || rinfo.first == new[new_reloc]);

  if (rinfo.rel_to_rela)
    {
      assert (sizeof (Elf32_Rel) * 3 == sizeof (Elf32_Rela) * 2);
      assert (sizeof (Elf64_Rel) * 3 == sizeof (Elf64_Rela) * 2);
      assert (new_reloc != -1);
      for (j = rinfo.first; j <= rinfo.last; ++j)
	{
	  dso->shdr[j].sh_size
	    = dso->shdr[j].sh_size / 3 * 2;
	  if (convert_rel_to_rela (dso, j))
	    goto error_out;
	  dso->shdr[j].sh_size = shdr[j].sh_size;
	}
    }

  /* Adjust .rel*.plt if necessary.  */
  rinfo.plt = move->old_to_new[rinfo.plt];
  if (new_plt != -1)
    {
      assert (rinfo.plt == new[new_plt]);
      if (rinfo.rel_to_rela_plt)
	{
	  assert (sizeof (Elf32_Rel) * 3 == sizeof (Elf32_Rela) * 2);
	  assert (sizeof (Elf64_Rel) * 3 == sizeof (Elf64_Rela) * 2);
	  dso->shdr[rinfo.first].sh_size
	    = dso->shdr[rinfo.first].sh_size / 3 * 2;
	  if (convert_rel_to_rela (dso, rinfo.plt))
	    goto error_out;
	  dso->shdr[rinfo.plt].sh_size = shdr[rinfo.plt].sh_size;
	}
    }

  /* Add new strings into .dynstr if necessary.  */
  if (new_dynstr != -1)
    {
      Elf_Data *data;
      char *ptr;

      i = new[new_dynstr];
      data = elf_getdata (dso->scn[i], NULL);
      assert (data->d_off == 0);
      data->d_buf = realloc (data->d_buf, dso->shdr[i].sh_size);
      if (data->d_buf == NULL)
	{
	  error (0, ENOMEM, "%s: Could not append names needed for .gnu.liblist to .dynstr",
		 dso->filename);
	  goto error_out;
	}
      ptr = data->d_buf + data->d_size;
      data->d_size = dso->shdr[i].sh_size;
      for (j = 0; j < ndeps - 1; ++j)
	if (liblist[j].l_name == 0)
	  {
	    liblist[j].l_name = ptr - (char *) data->d_buf;
	    ptr = stpcpy (ptr, info->sonames[j + 1]) + 1;
	  }
      assert (ptr == (char *) data->d_buf + data->d_size);
    }

  /* Create or update .sdynbss if necessary.  */
  if (new_sdynbss != -1)
    {
      Elf_Data *data;

      if (old_sdynbss == -1)
	{
	  dso->shdr[new_sdynbss] = dso->shdr[new_sdynbss + 1];

	  dso->shdr[new_sdynbss].sh_name = shstrtabadd (dso, ".sdynbss");
	  if (dso->shdr[new_sdynbss].sh_name == 0)
	    goto error_out;

	  dso->shdr[new_sdynbss].sh_size =
	    info->sdynbss_base + info->sdynbss_size
	    - dso->shdr[new_sdynbss].sh_addr;

	  dso->shdr[new_sdynbss + 1].sh_size
	    -= dso->shdr[new_sdynbss].sh_size;
	  dso->shdr[new_sdynbss + 1].sh_addr
	    += dso->shdr[new_sdynbss].sh_size;
	  dso->shdr[new_sdynbss + 1].sh_offset
	    += dso->shdr[new_sdynbss].sh_size;
	  dso->shdr[new_sdynbss].sh_type = SHT_PROGBITS;
	}
      else
	{
	  if (dso->shdr[new_sdynbss].sh_type != SHT_PROGBITS
	      || dso->shdr[new_sdynbss].sh_addr > info->sdynbss_base
	      || dso->shdr[new_sdynbss].sh_addr
		 + dso->shdr[new_sdynbss].sh_size
		 < info->sdynbss_base + info->sdynbss_size)
	    {
	      error (0, 0, "%s: Copy relocs don't point into .sdynbss section",
		     dso->filename);
	      goto error_out;
	    }
	}
      data = elf_getdata (dso->scn[new_sdynbss], NULL);
      free (data->d_buf);
      data->d_buf = info->sdynbss;
      info->sdynbss = NULL;
      data->d_off = info->sdynbss_base - dso->shdr[new_sdynbss].sh_addr;
      data->d_size = info->sdynbss_size;
      data->d_type = ELF_T_BYTE;
      if (old_sdynbss == -1)
	{
	  data = elf_getdata (dso->scn[new_sdynbss + 1], NULL);
	  assert (dso->shdr[new_sdynbss + 1].sh_type != SHT_NOBITS
		  || data->d_buf == NULL);
	  assert (data->d_size == dso->shdr[new_sdynbss].sh_size
				  + dso->shdr[new_sdynbss + 1].sh_size);
	  data->d_size -= dso->shdr[new_sdynbss].sh_size;
	}
    }

  /* Create or update .dynbss if necessary.  */
  if (new_dynbss != -1)
    {
      Elf_Data *data;

      if (old_dynbss == -1)
	{
	  GElf_Addr adj;

	  dso->shdr[new_dynbss] = dso->shdr[new_dynbss + 1];

	  dso->shdr[new_dynbss].sh_name = shstrtabadd (dso, ".dynbss");
	  if (dso->shdr[new_dynbss].sh_name == 0)
	    goto error_out;

	  dso->shdr[new_dynbss].sh_size =
	    info->dynbss_base + info->dynbss_size
	    - dso->shdr[new_dynbss].sh_addr;

	  dso->shdr[new_dynbss + 1].sh_size
	    -= dso->shdr[new_dynbss].sh_size;
	  dso->shdr[new_dynbss + 1].sh_addr
	    += dso->shdr[new_dynbss].sh_size;
	  dso->shdr[new_dynbss + 1].sh_offset
	    += dso->shdr[new_dynbss].sh_size;
	  dso->shdr[new_dynbss].sh_type = SHT_PROGBITS;

	  if (dso->shdr[new_dynbss + 1].sh_type == SHT_NOBITS)
	    {
	      GElf_Addr last_offset;

	      for (i = 0; i < dso->ehdr.e_phnum; ++i)
		if (dso->phdr[i].p_type == PT_LOAD
		    && dso->phdr[i].p_vaddr <= dso->shdr[new_dynbss].sh_addr
		    && dso->phdr[i].p_vaddr + dso->phdr[i].p_memsz
		       >= info->dynbss_base + info->dynbss_size)
		  break;
	      assert (i < dso->ehdr.e_phnum);

	      for (j = new_dynbss - 1; j; --j)
		{
		  if (dso->shdr[j].sh_addr < dso->phdr[i].p_vaddr)
		    break;
		  if (dso->shdr[j].sh_type == SHT_NOBITS)
		    {
		      error (0, 0, "%s: COPY relocs not present at start of first SHT_NOBITS section",
			     dso->filename);
		      goto error_out;
		    }
		}

	      if (dso->phdr[i].p_filesz
		  < info->dynbss_base + info->dynbss_size
		    - dso->phdr[i].p_vaddr)
		{
		  dso->phdr[i].p_filesz =
		    info->dynbss_base + info->dynbss_size
		    - dso->phdr[i].p_vaddr;
		  assert (dso->phdr[i].p_filesz <= dso->phdr[i].p_memsz);
		}

	      adj = dso->phdr[i].p_offset + dso->shdr[new_dynbss].sh_addr
		    - dso->phdr[i].p_vaddr - dso->shdr[new_dynbss].sh_offset;

	      dso->shdr[new_dynbss].sh_offset += adj;
	      dso->shdr[new_dynbss + 1].sh_offset += adj;

	      adj += dso->shdr[new_dynbss].sh_size;

	      for (j = new_dynbss + 2;
		   j < dso->ehdr.e_shnum
		   && (dso->shdr[j].sh_flags
		       & (SHF_WRITE | SHF_ALLOC | SHF_EXECINSTR));
		   ++j)
		if (dso->shdr[j].sh_addr >= dso->phdr[i].p_vaddr
					    + dso->phdr[i].p_memsz)
		  adj = (adj + dso->shdr[j].sh_addralign - 1)
			& ~(dso->shdr[j].sh_addralign - 1);

	      for (j = i + 1; j < dso->ehdr.e_phnum; ++j)
		if (dso->phdr[j].p_type == PT_LOAD
		    && dso->phdr[j].p_vaddr >= dso->shdr[new_dynbss].sh_addr)
		  {
		    dso->phdr[j].p_vaddr += adj;
		    dso->phdr[j].p_paddr += adj;
		    dso->phdr[j].p_offset += adj;
		  }

	      last_offset = dso->shdr[new_dynbss + 1].sh_offset;
	      for (j = new_dynbss + 2; j < dso->ehdr.e_shnum; ++j)
		if (dso->shdr[j].sh_type != SHT_NOBITS
		    || dso->shdr[j].sh_addr < dso->phdr[i].p_vaddr
		    || dso->shdr[j].sh_addr + dso->shdr[j].sh_size
		       > dso->phdr[i].p_vaddr + dso->phdr[i].p_memsz)
		  break;
		else
		  {
		    last_offset += dso->shdr[j].sh_addralign - 1;
		    last_offset &= ~(dso->shdr[j].sh_addralign - 1);
		    if (last_offset > dso->phdr[i].p_offset
				      + dso->phdr[i].p_filesz)
		      last_offset = dso->phdr[i].p_offset
				    + dso->phdr[i].p_filesz;
		    dso->shdr[j].sh_offset = last_offset;
		  }

	      while (j < dso->ehdr.e_shnum
		     && (dso->shdr[j].sh_flags
			 & (SHF_WRITE | SHF_ALLOC | SHF_EXECINSTR)))
		{
		  dso->shdr[j].sh_offset += adj;
		  dso->shdr[j++].sh_addr += adj;
		}

	      if (adjust_dso_nonalloc (dso, new_dynbss + 2,
				       dso->shdr[new_dynbss].sh_offset,
				       adj))
		goto error_out;
	    }
	}
      else
	{
	  if (dso->shdr[new_dynbss].sh_type != SHT_PROGBITS
	      || dso->shdr[new_dynbss].sh_addr > info->dynbss_base
	      || dso->shdr[new_dynbss].sh_addr
		 + dso->shdr[new_dynbss].sh_size
		 < info->dynbss_base + info->dynbss_size)
	    {
	      error (0, 0, "%s: Copy relocs don't point into .dynbss section",
		     dso->filename);
	      goto error_out;
	    }
	}
      data = elf_getdata (dso->scn[new_dynbss], NULL);
      free (data->d_buf);
      data->d_buf = info->dynbss;
      info->dynbss = NULL;
      data->d_off = info->dynbss_base - dso->shdr[new_dynbss].sh_addr;
      data->d_size = info->dynbss_size;
      data->d_type = ELF_T_BYTE;
      if (old_dynbss == -1)
	{
	  data = elf_getdata (dso->scn[new_dynbss + 1], NULL);
	  assert (dso->shdr[new_dynbss + 1].sh_type != SHT_NOBITS
		  || data->d_buf == NULL);
	  assert (data->d_size == dso->shdr[new_dynbss].sh_size
				  + dso->shdr[new_dynbss + 1].sh_size);
	  data->d_size -= dso->shdr[new_dynbss].sh_size;
	}
    }

  /* Create the liblist.  */
  i = new[new_liblist];
  dso->shdr[i].sh_flags = shdr[i].sh_flags;
  dso->shdr[i].sh_addralign = shdr[i].sh_addralign;
  dso->shdr[i].sh_entsize = shdr[i].sh_entsize;
  dso->shdr[i].sh_name = shstrtabadd (dso, ".gnu.liblist");
  if (dso->shdr[i].sh_name == 0)
    goto error_out;
  else
    {
      Elf_Data *data;

      dso->shdr[i].sh_link
	= new_dynstr != -1 ? new[new_dynstr] : move->old_to_new[dynstrndx];
      data = elf_getdata (dso->scn[i], NULL);
      data->d_type = ELF_T_WORD;
      data->d_size = (ndeps - 1) * sizeof (Elf32_Lib);
      free (data->d_buf);
      data->d_buf = liblist;
      liblist = NULL;
      data->d_off = 0;
      data->d_align = sizeof (GElf_Word);
      data->d_version = EV_CURRENT;
      if (set_dynamic (dso, DT_GNU_LIBLIST, dso->shdr[i].sh_addr, 1))
	goto error_out;
      if (set_dynamic (dso, DT_GNU_LIBLISTSZ, dso->shdr[i].sh_size, 1))
	goto error_out;
    }

  /* Create the conflict list if necessary.  */
  if (new_conflict != -1)
    {
      Elf_Data *data;

      i = new[new_conflict];
      data = elf_getdata (dso->scn[i], NULL);
      data->d_type = ELF_T_RELA;
      data->d_size = info->conflict_rela_size
		     * gelf_fsize (dso->elf, ELF_T_RELA, 1, EV_CURRENT);
      data->d_off = 0;
      data->d_align = gelf_fsize (dso->elf, ELF_T_ADDR, 1, EV_CURRENT);
      data->d_buf = realloc (data->d_buf, data->d_size);
      data->d_version = EV_CURRENT;
      if (data->d_buf == NULL)
	{
	  error (0, ENOMEM, "%s: Could not build .gnu.conflict section", dso->filename);
	  goto error_out;
	}
      for (j = 0; j < info->conflict_rela_size; ++j)
	gelfx_update_rela (dso->elf, data, j, info->conflict_rela + j);
      free (info->conflict_rela);
      info->conflict_rela = NULL;

      dso->shdr[i].sh_flags = shdr[i].sh_flags;
      dso->shdr[i].sh_addralign = shdr[i].sh_addralign;
      dso->shdr[i].sh_entsize = shdr[i].sh_entsize;
      for (j = 1; j < dso->ehdr.e_shnum; ++j)
	if (dso->shdr[j].sh_type == SHT_DYNSYM)
	  break;
      assert (j < dso->ehdr.e_shnum);
      dso->shdr[i].sh_link = j;
      dso->shdr[i].sh_name = shstrtabadd (dso, ".gnu.conflict");
      if (dso->shdr[i].sh_name == 0)
	goto error_out;
      if (set_dynamic (dso, DT_GNU_CONFLICT, dso->shdr[i].sh_addr, 1))
	goto error_out;
      if (set_dynamic (dso, DT_GNU_CONFLICTSZ, dso->shdr[i].sh_size, 1))
	goto error_out;
    }

  if (undo != -1)
    {
      Elf_Scn *scn;
      Elf_Data *data;
      GElf_Addr newoffset;

      dso->shdr[undo].sh_name = shstrtabadd (dso, ".gnu.prelink_undo");
      if (dso->shdr[undo].sh_name == 0)
	return 1;
      dso->shdr[undo].sh_offset = dso->shdr[undo - 1].sh_offset;
      if (dso->shdr[undo - 1].sh_type != SHT_NOBITS)
	dso->shdr[undo].sh_offset += dso->shdr[undo - 1].sh_size;
      dso->shdr[undo].sh_entsize = 1;
      dso->shdr[undo].sh_size = dso->undo.d_size;
      newoffset = dso->shdr[undo].sh_offset + dso->undo.d_align - 1;
      newoffset &= ~(dso->shdr[undo].sh_addralign - 1);
      if (adjust_dso_nonalloc (dso, undo + 1, dso->shdr[undo].sh_offset,
			       dso->undo.d_size + newoffset
			       - dso->shdr[undo].sh_offset))
	return 1;
      dso->shdr[undo].sh_offset = newoffset;
      scn = dso->scn[undo];
      data = elf_getdata (scn, NULL);
      assert (data != NULL && elf_getdata (scn, data) == NULL);
      free (data->d_buf);
      *data = dso->undo;
      dso->undo.d_buf = NULL;
    }

  if (update_dynamic_tags (dso, dso->shdr, old_shdr, move))
    goto error_out;

  if (update_dynamic_rel (dso, &rinfo))
    goto error_out;

  free (move);
  return 0;

error_out:
  free (liblist);
  free (move);
  return 1;
}
