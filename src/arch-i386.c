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
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <locale.h>
#include <error.h>
#include <argp.h>
#include <stdlib.h>

#include "prelink.h"

static int
i386_adjust_dyn (DSO *dso, int n, GElf_Dyn *dyn, GElf_Addr start,
		 GElf_Addr adjust)
{
  if (dyn->d_tag == DT_PLTGOT)
    {
      int sec = addr_to_sec (dso, dyn->d_un.d_ptr);
      Elf32_Addr data;

      if (sec == -1)
	return 1;

      data = read_ule32 (dso, dyn->d_un.d_ptr);
      /* If .got[0] points to _DYNAMIC, it needs to be adjusted.  */
      if (data == dso->shdr[n].sh_addr && data >= start)
	write_le32 (dso, dyn->d_un.d_ptr, data + adjust);

      data = read_ule32 (dso, dyn->d_un.d_ptr + 4);
      /* If .got[1] points to .plt + 0x16, it needs to be adjusted.  */
      if (data && data >= start)
	{
	  int i;

	  for (i = 1; i < dso->ehdr.e_shnum; i++)
	    if (data == dso->shdr[i].sh_addr + 0x16
		&& dso->shdr[i].sh_type == SHT_PROGBITS
		&& strcmp (strptr (dso, dso->ehdr.e_shstrndx,
					dso->shdr[i].sh_name), ".plt") == 0)
	      {
		write_le32 (dso, dyn->d_un.d_ptr + 4, data + adjust);
		break;
	      }
	}
    }
  return 0;
}

static int
i386_adjust_rel (DSO *dso, GElf_Rel *rel, GElf_Addr start,
		 GElf_Addr adjust)
{
  Elf32_Addr data;
  switch (GELF_R_TYPE (rel->r_info))
    {
    case R_386_RELATIVE:
    case R_386_JMP_SLOT:
      data = read_ule32 (dso, rel->r_offset);
      if (data >= start)
	write_le32 (dso, rel->r_offset, data + adjust);
      break;
    }
  return 0;
}

static int
i386_adjust_rela (DSO *dso, GElf_Rela *rela, GElf_Addr start,
		  GElf_Addr adjust)
{
  switch (GELF_R_TYPE (rela->r_info))
    {
    case R_386_RELATIVE:
    case R_386_JMP_SLOT:
      if (rela->r_addend >= start)
	{
	  rela->r_addend += adjust;
	  /* Write it to the memory location as well.
	     Not necessary, but we can do it.  */
	  write_le32 (dso, rela->r_offset, rela->r_addend);
	}
      break;
    }
  return 0;
}

static int
i386_prelink_rel (struct prelink_info *info, GElf_Rel *rel)
{
  DSO *dso;
  GElf_Addr value;

  if (GELF_R_TYPE (rel->r_info) == R_386_RELATIVE)
    /* Fast path: nothing to do.  */
    return 0;
  dso = info->dso;
  value = info->resolve (info, GELF_R_SYM (rel->r_info),
			 GELF_R_TYPE (rel->r_info));
  switch (GELF_R_TYPE (rel->r_info))    
    {
    case R_386_GLOB_DAT:
    case R_386_JMP_SLOT:
      write_le32 (dso, rel->r_offset, value);
      break;
    case R_386_32:
      write_le32 (dso, rel->r_offset,
		  read_ule32 (dso, rel->r_offset) + value);
      break;
    case R_386_PC32:
      write_le32 (dso, rel->r_offset,
		  read_ule32 (dso, rel->r_offset)
		  + value - rel->r_offset);
      break;
    case R_386_COPY:
      if (dso->ehdr.e_type == ET_EXEC)
	/* COPY relocs are handled specially in generic code.  */
	return 0;
      error (0, 0, "%s: R_386_COPY reloc in shared library?", dso->filename);
      return 1;
    default:
      error (0, 0, "%s: Unknown i386 relocation type %d", dso->filename,
	     (int) GELF_R_TYPE (rel->r_info));
      return 1;
    }
  return 0;
}

static int
i386_prelink_rela (struct prelink_info *info, GElf_Rela *rela)
{
  DSO *dso;
  GElf_Addr value;

  if (GELF_R_TYPE (rela->r_info) == R_386_RELATIVE)
    /* Fast path: nothing to do.  */
    return 0;
  dso = info->dso;
  value = info->resolve (info, GELF_R_SYM (rela->r_info),
			 GELF_R_TYPE (rela->r_info));
  switch (GELF_R_TYPE (rela->r_info))    
    {
    case R_386_GLOB_DAT:
    case R_386_JMP_SLOT:
      write_le32 (dso, rela->r_offset, value + rela->r_addend);
      break;
    case R_386_32:
      write_le32 (dso, rela->r_offset, value + rela->r_addend);
      break;
    case R_386_PC32:
      write_le32 (dso, rela->r_offset, value + rela->r_addend - rela->r_offset);
      break;
    case R_386_COPY:
      error (0, 0, "R_386_COPY not handled yet");
      return 1;
    default:
      error (0, 0, "%s: Unknown i386 relocation type %d", dso->filename,
	     (int) GELF_R_TYPE (rela->r_info));
      return 1;
    }
  return 0;
}

static int
i386_apply_conflict_rela (struct prelink_info *info, GElf_Rela *rela,
			  char *buf)
{
  Elf32_Addr value;
  unsigned int i;

  switch (GELF_R_TYPE (rela->r_info))    
    {
    case R_386_GLOB_DAT:
    case R_386_JMP_SLOT:
    case R_386_32:
    case R_386_PC32:
      value = rela->r_addend;
      for (i = 0; i < sizeof (Elf32_Addr); ++i, value >>= 8)
	*buf++ = value;
      break;
    default:
      abort ();
    }
  return 0;
}

static int
i386_prelink_conflict_rel (struct prelink_info *info, GElf_Rel *rel)
{
  DSO *dso;
  GElf_Addr value, oldvalue;
  struct prelink_conflict *conflict;
  GElf_Rela *ret;

  if (GELF_R_TYPE (rel->r_info) == R_386_RELATIVE)
    /* Fast path: nothing to do.  */
    return 0;
  dso = info->dso;
  conflict = prelink_conflict (info, GELF_R_SYM (rel->r_info),
			       GELF_R_TYPE (rel->r_info));
  if (conflict == NULL)
    return 0;
  value = conflict->lookupent->base + conflict->lookupval;
  ret = prelink_conflict_add_rela (info);
  if (ret == NULL)
    return 1;
  ret->r_offset = rel->r_offset;
  ret->r_info = GELF_R_INFO (0, GELF_R_TYPE (rel->r_info));
  switch (GELF_R_TYPE (rel->r_info))    
    {
    case R_386_GLOB_DAT:
    case R_386_JMP_SLOT:
      ret->r_addend = value;
      break;
    case R_386_32:
    case R_386_PC32:
      oldvalue = read_ule32 (dso, rel->r_offset);
      value += oldvalue - (conflict->conflictent->base + conflict->conflictval);
      ret->r_addend = value;
      break;
    case R_386_COPY:
      error (0, 0, "R_386_COPY should not be present in shared libraries");
      return 1;
    default:
      error (0, 0, "%s: Unknown i386 relocation type %d", dso->filename,
	     (int) GELF_R_TYPE (rel->r_info));
      return 1;
    }
  return 0;
}

static int
i386_prelink_conflict_rela (struct prelink_info *info, GElf_Rela *rela)
{
  DSO *dso;
  GElf_Addr value;
  struct prelink_conflict *conflict;
  GElf_Rela *ret;

  if (GELF_R_TYPE (rela->r_info) == R_386_RELATIVE)
    /* Fast path: nothing to do.  */
    return 0;
  dso = info->dso;
  conflict = prelink_conflict (info, GELF_R_SYM (rela->r_info),
			       GELF_R_TYPE (rela->r_info));
  if (conflict == NULL)
    return 0;
  value = conflict->lookupent->base + conflict->lookupval;
  ret = prelink_conflict_add_rela (info);
  if (ret == NULL)
    return 1;
  ret->r_offset = rela->r_offset;
  ret->r_info = GELF_R_INFO (0, GELF_R_TYPE (rela->r_info));
  switch (GELF_R_TYPE (rela->r_info))    
    {
    case R_386_GLOB_DAT:
    case R_386_JMP_SLOT:
      ret->r_addend = value + rela->r_addend;
      break;
    case R_386_32:
    case R_386_PC32:
      value += rela->r_addend;
      ret->r_addend = value;
      break;
    case R_386_COPY:
      error (0, 0, "R_386_COPY should not be present in shared libraries");
      return 1;
    default:
      error (0, 0, "%s: Unknown i386 relocation type %d", dso->filename,
	     (int) GELF_R_TYPE (rela->r_info));
      return 1;
    }
  return 0;
}

static int
i386_rel_to_rela (DSO *dso, GElf_Rel *rel, GElf_Rela *rela)
{
  rela->r_offset = rel->r_offset;
  rela->r_info = rel->r_info;
  switch (GELF_R_TYPE (rel->r_info))
    {
    case R_386_JMP_SLOT:
      /* We should be never converting .rel.plt into .rela.plt.  */
      abort ();
    case R_386_RELATIVE:
    case R_386_32:
    case R_386_PC32:
      rela->r_addend = read_ule32 (dso, rel->r_offset);
      break;
    case R_386_COPY:
    case R_386_GLOB_DAT:
      rela->r_addend = 0;
      break;
    }
  return 0;
}

static int
i386_need_rel_to_rela (DSO *dso, int first, int last)
{
  Elf_Data *data;
  Elf_Scn *scn;
  Elf32_Rel *rel, *relend;

  while (first < last)
    {
      data = NULL;
      scn = elf_getscn (dso->elf, first++);
      while ((data = elf_getdata (scn, data)) != NULL)
	{
	  rel = (Elf32_Rel *) data->d_buf;
	  relend = rel + data->d_size / sizeof (Elf32_Rel);
	  for (; rel < relend; rel++)
	    switch (ELF32_R_TYPE (rel->r_info))
	      {
	      case R_386_32:
	      case R_386_PC32:
		return 1;
	      }
        }
    }
  return 0;
}

static int
i386_arch_prelink (DSO *dso)
{
  int i;

  if (dso->info[DT_PLTGOT])
    {
      /* Write address of .plt + 0x16 into got[1].
	 .plt + 0x16 is what got[3] contains unless prelinking.  */
      int sec = addr_to_sec (dso, dso->info[DT_PLTGOT]);
      Elf32_Addr data;

      if (sec == -1)
	return 1;

      for (i = 1; i < dso->ehdr.e_shnum; i++)
	if (dso->shdr[i].sh_type == SHT_PROGBITS
	    && ! strcmp (strptr (dso, dso->ehdr.e_shstrndx,
				 dso->shdr[i].sh_name),
			 ".plt"))
	break;

      assert (i < dso->ehdr.e_shnum);
      data = dso->shdr[i].sh_addr + 0x16;
      write_le32 (dso, dso->info[DT_PLTGOT] + 4, data);
    }

  return 0;
}

static int
i386_reloc_size (int reloc_type)
{
  assert (reloc_type != R_386_COPY);
  return 4;
}

PL_ARCH = {
  .class = ELFCLASS32,
  .machine = EM_386,
  .R_JMP_SLOT = R_386_JMP_SLOT,
  .R_COPY = R_386_COPY,
  .R_RELATIVE = R_386_RELATIVE,
  .adjust_dyn = i386_adjust_dyn,
  .adjust_rel = i386_adjust_rel,
  .adjust_rela = i386_adjust_rela,
  .prelink_rel = i386_prelink_rel,
  .prelink_rela = i386_prelink_rela,
  .prelink_conflict_rel = i386_prelink_conflict_rel,
  .prelink_conflict_rela = i386_prelink_conflict_rela,
  .apply_conflict_rela = i386_apply_conflict_rela,
  .rel_to_rela = i386_rel_to_rela,
  .need_rel_to_rela = i386_need_rel_to_rela,
  .reloc_size = i386_reloc_size,
  .arch_prelink = i386_arch_prelink,
  /* Although TASK_UNMAPPED_BASE is 0x40000000, we leave some
     area so that mmap of /etc/ld.so.cache and ld.so's malloc
     does not take some library's VA slot.
     Also, if this guard area isn't too small, typically
     even dlopened libraries will get the slots they desire.  */
  .mmap_base = 0x41000000,
  .mmap_end =  0x50000000,
  .page_size = 0x1000
};
