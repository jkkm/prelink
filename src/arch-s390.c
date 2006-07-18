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
s390_adjust_dyn (DSO *dso, int n, GElf_Dyn *dyn, GElf_Addr start,
		 GElf_Addr adjust)
{
  if (dyn->d_tag == DT_PLTGOT)
    {
      int sec = addr_to_sec (dso, dyn->d_un.d_ptr);
      Elf64_Addr data;

      if (sec == -1)
	return 1;

      data = read_ube32 (dso, dyn->d_un.d_ptr);
      /* If .got[0] points to _DYNAMIC, it needs to be adjusted.  */
      if (data == dso->shdr[n].sh_addr && data >= start)
	write_be32 (dso, dyn->d_un.d_ptr, data + adjust);

      data = read_ube32 (dso, dyn->d_un.d_ptr + 4);
      /* If .got[1] points to .plt + 0x20, it needs to be adjusted.  */
      if (data && data >= start)
	{
	  int i;

	  for (i = 1; i < dso->ehdr.e_shnum; i++)
	    if (data == dso->shdr[i].sh_addr + 0x20
		&& dso->shdr[i].sh_type == SHT_PROGBITS
		&& strcmp (strptr (dso, dso->ehdr.e_shstrndx,
					dso->shdr[i].sh_name), ".plt") == 0)
	      {
		write_be32 (dso, dyn->d_un.d_ptr + 4, data + adjust);
		break;
	      }
	}
    }
  return 0;
}

static int
s390_adjust_rel (DSO *dso, GElf_Rel *rel, GElf_Addr start,
		   GElf_Addr adjust)
{
  error (0, 0, "%s: S390 doesn't support REL relocs", dso->filename);
  return 1;
}

static int
s390_adjust_rela (DSO *dso, GElf_Rela *rela, GElf_Addr start,
		  GElf_Addr adjust)
{
  Elf64_Addr addr;

  switch (GELF_R_TYPE (rela->r_info))
    {
    case R_390_RELATIVE:
      if (rela->r_addend >= start)
	rela->r_addend += adjust;
      break;
    case R_390_JMP_SLOT:
      addr = read_ube32 (dso, rela->r_offset);
      if (addr >= start)
	write_be32 (dso, rela->r_offset, addr + adjust);
      break;
    }
  return 0;
}

static int
s390_prelink_rel (struct prelink_info *info, GElf_Rel *rel, GElf_Addr reladdr)
{
  error (0, 0, "%s: S390 doesn't support REL relocs", info->dso->filename);
  return 1;
}

static int
s390_prelink_rela (struct prelink_info *info, GElf_Rela *rela,
		   GElf_Addr relaaddr)
{
  DSO *dso = info->dso;
  GElf_Addr value;

  if (GELF_R_TYPE (rela->r_info) == R_390_NONE)
    return 0;
  else if (GELF_R_TYPE (rela->r_info) == R_390_RELATIVE)
    {
      write_be32 (dso, rela->r_offset, rela->r_addend);
      return 0;
    }
  value = info->resolve (info, GELF_R_SYM (rela->r_info),
			 GELF_R_TYPE (rela->r_info));
  switch (GELF_R_TYPE (rela->r_info))    
    {
    case R_390_GLOB_DAT:
    case R_390_JMP_SLOT:
      write_be32 (dso, rela->r_offset, value);
      break;
    case R_390_32:
      write_be32 (dso, rela->r_offset, value + rela->r_addend);
      break;
    case R_390_PC32:
      write_be32 (dso, rela->r_offset, value + rela->r_addend - rela->r_offset);
      break;
    case R_390_COPY:
      if (dso->ehdr.e_type == ET_EXEC)
	/* COPY relocs are handled specially in generic code.  */
	return 0;
      error (0, 0, "%s: R_390_COPY reloc in shared library?", dso->filename);
      return 1;
    default:
      error (0, 0, "%s: Unknown S390 relocation type %d", dso->filename,
	     (int) GELF_R_TYPE (rela->r_info));
      return 1;
    }
  return 0;
}

static int
s390_apply_conflict_rela (struct prelink_info *info, GElf_Rela *rela,
			  char *buf)
{
  switch (GELF_R_TYPE (rela->r_info))    
    {
    case R_390_32:
      buf_write_be32 (buf, rela->r_addend);
      break;
    default:
      abort ();
    }
  return 0;
}

static int
s390_apply_rel (struct prelink_info *info, GElf_Rel *rel, char *buf)
{
  error (0, 0, "%s: S390 doesn't support REL relocs", info->dso->filename);
  return 1;
}

static int
s390_apply_rela (struct prelink_info *info, GElf_Rela *rela, char *buf)
{
  GElf_Addr value;

  value = info->resolve (info, GELF_R_SYM (rela->r_info),
			 GELF_R_TYPE (rela->r_info));
  switch (GELF_R_TYPE (rela->r_info))    
    {
    case R_390_NONE:
      break;
    case R_390_GLOB_DAT:
    case R_390_JMP_SLOT:
      buf_write_be32 (buf, value);
      break;
    case R_390_32:
      buf_write_be32 (buf, value + rela->r_addend);
      break;
    case R_390_PC32:
      buf_write_be32 (buf, value + rela->r_addend - rela->r_offset);
      break;
    case R_390_COPY:
      abort ();
    case R_390_RELATIVE:
      error (0, 0, "%s: R_390_RELATIVE in ET_EXEC object?", info->dso->filename);
      return 1;
    default:
      return 1;
    }
  return 0;
}

static int
s390_prelink_conflict_rel (DSO *dso, struct prelink_info *info, GElf_Rel *rel,
			   GElf_Addr reladdr)
{
  error (0, 0, "%s: S390 doesn't support REL relocs", dso->filename);
  return 1;
}

static int
s390_prelink_conflict_rela (DSO *dso, struct prelink_info *info,
			    GElf_Rela *rela, GElf_Addr relaaddr)
{
  GElf_Addr value;
  struct prelink_conflict *conflict;
  GElf_Rela *ret;

  if (GELF_R_TYPE (rela->r_info) == R_390_RELATIVE
      || GELF_R_TYPE (rela->r_info) == R_390_NONE)
    /* Fast path: nothing to do.  */
    return 0;
  conflict = prelink_conflict (info, GELF_R_SYM (rela->r_info),
			       GELF_R_TYPE (rela->r_info));
  if (conflict == NULL)
    return 0;
  value = conflict->lookupent->base + conflict->lookupval;
  ret = prelink_conflict_add_rela (info);
  if (ret == NULL)
    return 1;
  ret->r_offset = rela->r_offset;
  ret->r_info = GELF_R_INFO (0, R_390_32);
  switch (GELF_R_TYPE (rela->r_info))    
    {
    case R_390_GLOB_DAT:
    case R_390_JMP_SLOT:
      ret->r_addend = value;
      break;
    case R_390_32:
      ret->r_addend = value + rela->r_addend;
      break;
    case R_390_PC32:
      ret->r_addend = value + rela->r_addend - rela->r_offset;
      break;
    case R_390_COPY:
      error (0, 0, "R_390_COPY should not be present in shared libraries");
      return 1;
    default:
      error (0, 0, "%s: Unknown S390 relocation type %d", dso->filename,
	     (int) GELF_R_TYPE (rela->r_info));
      return 1;
    }
  return 0;
}

static int
s390_rel_to_rela (DSO *dso, GElf_Rel *rel, GElf_Rela *rela)
{
  error (0, 0, "%s: S390 doesn't support REL relocs", dso->filename);
  return 1;
}

static int
s390_need_rel_to_rela (DSO *dso, int first, int last)
{
  return 0;
}

static int
s390_arch_prelink (DSO *dso)
{
  int i;

  if (dso->info[DT_PLTGOT])
    {
      /* Write address of .plt + 0x20 into got[1].
	 .plt + 0x20 is what got[3] contains unless prelinking.  */
      int sec = addr_to_sec (dso, dso->info[DT_PLTGOT]);
      Elf64_Addr data;

      if (sec == -1)
	return 1;

      for (i = 1; i < dso->ehdr.e_shnum; i++)
	if (dso->shdr[i].sh_type == SHT_PROGBITS
	    && ! strcmp (strptr (dso, dso->ehdr.e_shstrndx,
				 dso->shdr[i].sh_name),
			 ".plt"))
	break;

      assert (i < dso->ehdr.e_shnum);
      data = dso->shdr[i].sh_addr + 0x20;
      write_be32 (dso, dso->info[DT_PLTGOT] + 4, data);
    }

  return 0;
}

static int
s390_reloc_size (int reloc_type)
{
  return 4;
}

static int
s390_reloc_class (int reloc_type)
{
  switch (reloc_type)
    {
    case R_390_COPY: return RTYPE_CLASS_COPY;
    case R_390_JMP_SLOT: return RTYPE_CLASS_PLT;
    default: return RTYPE_CLASS_VALID;
    }
}

PL_ARCH = {
  .class = ELFCLASS32,
  .machine = EM_S390,
  .alternate_machine = { 0xA390 },
  .R_JMP_SLOT = R_390_JMP_SLOT,
  .R_COPY = R_390_COPY,
  .R_RELATIVE = R_390_RELATIVE,
  .adjust_dyn = s390_adjust_dyn,
  .adjust_rel = s390_adjust_rel,
  .adjust_rela = s390_adjust_rela,
  .prelink_rel = s390_prelink_rel,
  .prelink_rela = s390_prelink_rela,
  .prelink_conflict_rel = s390_prelink_conflict_rel,
  .prelink_conflict_rela = s390_prelink_conflict_rela,
  .apply_conflict_rela = s390_apply_conflict_rela,
  .apply_rel = s390_apply_rel,
  .apply_rela = s390_apply_rela,
  .rel_to_rela = s390_rel_to_rela,
  .need_rel_to_rela = s390_need_rel_to_rela,
  .reloc_size = s390_reloc_size,
  .reloc_class = s390_reloc_class,
  .max_reloc_size = 4,
  .arch_prelink = s390_arch_prelink,
  /* Although TASK_UNMAPPED_BASE is 0x40000000, we leave some
     area so that mmap of /etc/ld.so.cache and ld.so's malloc
     does not take some library's VA slot.
     Also, if this guard area isn't too small, typically
     even dlopened libraries will get the slots they desire.  */
  .mmap_base = 0x41000000,
  .mmap_end =  0x50000000,
  .page_size = 0x1000
};
