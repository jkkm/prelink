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
ia64_adjust_dyn (DSO *dso, int n, GElf_Dyn *dyn, GElf_Addr start,
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
ia64_adjust_rel (DSO *dso, GElf_Rel *rel, GElf_Addr start,
		 GElf_Addr adjust)
{
  error (0, 0, "%s: IA-64 doesn't support REL relocs", dso->filename);
  return 1;
}

static int
ia64_adjust_rela (DSO *dso, GElf_Rela *rela, GElf_Addr start,
		  GElf_Addr adjust)
{
  if ((GELF_R_TYPE (rela->r_info) & ~3) == R_IA64_REL32MSB
      && rela->r_addend >= start)
    {
      rela->r_addend += adjust;
      switch (GELF_R_TYPE (rela->r_info) & 3)
	{
	case 0: write_be32 (dso, rela->r_offset, rela->r_addend); break;
	case 1: write_le32 (dso, rela->r_offset, rela->r_addend); break;
	case 2: write_be64 (dso, rela->r_offset, rela->r_addend); break;
	case 3: write_le64 (dso, rela->r_offset, rela->r_addend); break;
	}
    }
  else if ((GELF_R_TYPE (rela->r_info) & ~1) == R_IA64_IPLTMSB)
    {
      GElf_Addr val, gp;

      if (GELF_R_TYPE (rela->r_info) & 1)
	{
	  val = read_le64 (dso, rela->r_offset);
	  gp = read_le64 (dso, rela->r_offset + 8);
	}
      else
	{
	  val = read_be64 (dso, rela->r_offset);
	  gp = read_be64 (dso, rela->r_offset + 8);
	}
      if (gp == dso->info[DT_PLTGOT])
	{
	  if (val >= start)
	    val += adjust;
	  if (gp >= start)
	    gp += adjust;
	}
      if (GELF_R_TYPE (rela->r_info) & 1)
	{
	  write_le64 (dso, rela->r_offset, val);
	  write_le64 (dso, rela->r_offset + 8, gp);
	}
      else
	{
	  write_le64 (dso, rela->r_offset, val);
	  write_le64 (dso, rela->r_offset + 8, gp);
	}
    }
  return 0;
}

static int
ia64_prelink_rel (struct prelink_info *info, GElf_Rel *rel, GElf_Addr reladdr)
{
  error (0, 0, "%s: IA-64 doesn't support REL relocs", info->dso->filename);
  return 1;
}

static int
ia64_prelink_rela (struct prelink_info *info, GElf_Rela *rela,
		   GElf_Addr relaaddr)
{
  DSO *dso;
  GElf_Addr value;

  if ((GELF_R_TYPE (rela->r_info) & ~3) == R_IA64_REL32MSB
      || GELF_R_TYPE (rela->r_info) == R_IA64_NONE)
    /* Fast path: nothing to do.  */
    return 0;
  dso = info->dso;
  value = info->resolve (info, GELF_R_SYM (rela->r_info),
			 GELF_R_TYPE (rela->r_info));
  value += rela->r_addend;
  if ((GELF_R_TYPE (rela->r_info) & ~3) == R_IA64_DIR32MSB)
    {
      /* Nothing to do.  */
    }
  else if (GELF_R_TYPE (rela->r_info) & ~3) == R_IA64_PCREL32MSB)
    {
      value -= rela->r_offset & -16;
    }
  else if (GELF_R_TYPE (rela->r_info) & ~3) == R_IA64_FPTR32MSB)
    {
      /* FIXME */
    }
  else if (GELF_R_TYPE (rela->r_info) & ~1) == R_IA64_IPLTMSB)
    {
      GElf_Addr gp = info->resolveent->pltgot;

      if (GELF_R_TYPE (rela->r_info) & 1)
	{
	  write_le64 (dso, rela->r_offset, value);
	  write_le64 (dso, rela->r_offset + 8, gp);
	}
      else
	{
	  write_be64 (dso, rela->r_offset, value);
	  write_be64 (dso, rela->r_offset + 8, gp);
	}

      return 0;
    }
  else
    {
      error (0, 0, "%s: Unknown ia64 relocation type %d", dso->filename,
	     (int) GELF_R_TYPE (rela->r_info));
      return 1;
    }

  switch (GELF_R_TYPE (rela->r_info) & 3)
    {
    case 0: write_be32 (dso, rela->r_offset, value); break;
    case 1: write_le32 (dso, rela->r_offset, value); break;
    case 2: write_be64 (dso, rela->r_offset, value); break;
    case 3: write_le64 (dso, rela->r_offset, value); break;
    }
  return 0;
}

static int
ia64_apply_conflict_rela (struct prelink_info *info, GElf_Rela *rela,
			  char *buf)
{
  switch (GELF_R_TYPE (rela->r_info))    
    {
    case R_386_GLOB_DAT:
    case R_386_JMP_SLOT:
    case R_386_32:
    case R_386_PC32:
      buf_write_le32 (buf, rela->r_addend);
      break;
    default:
      abort ();
    }
  return 0;
}

static int
ia64_apply_rel (struct prelink_info *info, GElf_Rel *rel, char *buf)
{
  error (0, 0, "%s: IA-64 doesn't support REL relocs", info->dso->filename);
  return 1;
}

static int
ia64_apply_rela (struct prelink_info *info, GElf_Rela *rela, char *buf)
{
  GElf_Addr value;

  value = info->resolve (info, GELF_R_SYM (rela->r_info),
			 GELF_R_TYPE (rela->r_info));
  switch (GELF_R_TYPE (rela->r_info))    
    {
    case R_386_GLOB_DAT:
    case R_386_JMP_SLOT:
    case R_386_32:
      buf_write_le32 (buf, value + rela->r_addend);
      break;
    case R_386_PC32:
      buf_write_le32 (buf, value + rela->r_addend - rela->r_offset);
      break;
    case R_386_COPY:
      abort ();
    case R_386_RELATIVE:
      error (0, 0, "%s: R_386_RELATIVE in ET_EXEC object?", info->dso->filename);
      return 1;
    default:
      return 1;
    }
  return 0;
}

static int
ia64_prelink_conflict_rel (DSO *dso, struct prelink_info *info, GElf_Rel *rel,
			   GElf_Addr reladdr)
{
  error (0, 0, "%s: IA-64 doesn't support REL relocs", dso->filename);
  return 1;
}

static int
ia64_prelink_conflict_rela (DSO *dso, struct prelink_info *info,
			    GElf_Rela *rela, GElf_Addr relaaddr)
{
  GElf_Addr value;
  struct prelink_conflict *conflict;
  GElf_Rela *ret;

  if (GELF_R_TYPE (rela->r_info) == R_386_RELATIVE)
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
      error (0, 0, "%s: Unknown ia64 relocation type %d", dso->filename,
	     (int) GELF_R_TYPE (rela->r_info));
      return 1;
    }
  return 0;
}

static int
ia64_rel_to_rela (DSO *dso, GElf_Rel *rel, GElf_Rela *rela)
{
  error (0, 0, "%s: IA-64 doesn't support REL relocs", dso->filename);
  return 1;
}

static int
ia64_need_rel_to_rela (DSO *dso, int first, int last)
{
  return 0;
}

static int
ia64_arch_prelink (DSO *dso)
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
ia64_reloc_size (int reloc_type)
{
  assert (reloc_type != R_386_COPY);
  return 4;
}

static int
ia64_reloc_class (int reloc_type)
{
  switch (reloc_type)
    {
    case R_IA64_IPLTLSB:
    case R_IA64_IPLTMSB:
      return RTYPE_CLASS_PLT;
    default: return RTYPE_CLASS_VALID;
    }
}

PL_ARCH = {
  .class = ELFCLASS64,
  .machine = EM_IA64,
  .alternate_machine = { EM_NONE },
  .R_JMP_SLOT = R_IA64_IPLTLSB,
  .R_COPY = -1,
  .R_RELATIVE = R_IA64_REL64LSB,
  .dynamic_linker = "/lib/ld-linux-ia64.so.2",
  .adjust_dyn = ia64_adjust_dyn,
  .adjust_rel = ia64_adjust_rel,
  .adjust_rela = ia64_adjust_rela,
  .prelink_rel = ia64_prelink_rel,
  .prelink_rela = ia64_prelink_rela,
  .prelink_conflict_rel = ia64_prelink_conflict_rel,
  .prelink_conflict_rela = ia64_prelink_conflict_rela,
  .apply_conflict_rela = ia64_apply_conflict_rela,
  .apply_rel = ia64_apply_rel,
  .apply_rela = ia64_apply_rela,
  .rel_to_rela = ia64_rel_to_rela,
  .need_rel_to_rela = ia64_need_rel_to_rela,
  .reloc_size = ia64_reloc_size,
  .reloc_class = ia64_reloc_class,
  .max_reloc_size = 8,
  .arch_prelink = ia64_arch_prelink,
  /* Although TASK_UNMAPPED_BASE is 0x40000000, we leave some
     area so that mmap of /etc/ld.so.cache and ld.so's malloc
     does not take some library's VA slot.
     Also, if this guard area isn't too small, typically
     even dlopened libraries will get the slots they desire.  */
  .mmap_base = 0x41000000,
  .mmap_end =  0x50000000,
  .page_size = 0x1000
};
