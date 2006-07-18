/* Copyright (C) 2002 Red Hat, Inc.
   Written by Jakub Jelinek <jakub@redhat.com>, 2002.

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
#include "layout.h"

static int
ppc64_adjust_dyn (DSO *dso, int n, GElf_Dyn *dyn, GElf_Addr start,
		 GElf_Addr adjust)
{
  if (dyn->d_tag == DT_PLTGOT)
    {
      int i;

      for (i = 1; i < dso->ehdr.e_shnum; ++i)
	if (! strcmp (strptr (dso, dso->ehdr.e_shstrndx,
			      dso->shdr[i].sh_name), ".got"))
	  {
	    Elf64_Addr data;

	    data = read_ube64 (dso, dso->shdr[i].sh_addr);
	    /* .got[0] points to .toc, it needs to be adjusted.  */
	    if (data >= start)
	      write_be64 (dso, dso->shdr[i].sh_addr, data + adjust);
	    break;
	  }
    }

  return 0;
}

static int
ppc64_adjust_rel (DSO *dso, GElf_Rel *rel, GElf_Addr start,
		 GElf_Addr adjust)
{
  error (0, 0, "%s: PowerPC64 doesn't support REL relocs", dso->filename);
  return 1;
}

static int
ppc64_adjust_rela (DSO *dso, GElf_Rela *rela, GElf_Addr start,
		  GElf_Addr adjust)
{
  if (GELF_R_TYPE (rela->r_info) == R_PPC64_RELATIVE)
    {
      if (rela->r_addend >= start)
	rela->r_addend += adjust;
    }
  return 0;
}

static int
ppc64_prelink_rel (struct prelink_info *info, GElf_Rel *rel,
		   GElf_Addr reladdr)
{
  error (0, 0, "%s: PowerPC64 doesn't support REL relocs", info->dso->filename);
  return 1;
}

static void
ppc64_fixup_plt (DSO *dso, GElf_Rela *rela, GElf_Addr value)
{
XXX
  Elf32_Sword disp = value - rela->r_offset;

  if (disp >= -0x2000000 && disp < 0x2000000)
    {
      /* b value  */
      write_be32 (dso, rela->r_offset, 0x48000000 | (disp & 0x3fffffc));
    }
  else if ((Elf32_Addr) value >= -0x2000000 || value < 0x2000000)
    {
      /* ba value  */
      write_be32 (dso, rela->r_offset, 0x48000002 | (value & 0x3fffffc));
    }
  else
    {
      Elf32_Addr plt = dso->info[DT_PLTGOT];

      if (rela->r_offset - plt < (8192 * 2 + 18) * 4)
	{
	  Elf32_Word index = (rela->r_offset - plt - 18 * 4) / (4 * 2);
	  Elf32_Word count = dso->info[DT_PLTRELSZ] / sizeof (Elf32_Rela);
	  Elf32_Addr data;

	  data = plt + (18 + 2 * count
			+ (count > 8192 ? (count - 8192) * 2 : 0)) * 4;
	  write_be32 (dso, data + 4 * index, value);
	  /* li %r11, 4*index
	     b .plt+0  */
	  write_be32 (dso, rela->r_offset,
		      0x39600000 | ((index * 4) & 0xffff));
	  write_be32 (dso, rela->r_offset + 4,
		      0x48000000 | ((plt - rela->r_offset - 4) & 0x3fffffc));
	}
      else
	{
	  /* lis %r12, %hi(finaladdr)
	     addi %r12, %r12, %lo(finaladdr)
	     mtctr %r12
	     bctr  */
	  write_be32 (dso, rela->r_offset,
		      0x39800000 | (((value + 0x8000) >> 16) & 0xffff));
	  write_be32 (dso, rela->r_offset + 4, 0x398c0000 | (value & 0xffff));
	  write_be32 (dso, rela->r_offset + 8, 0x7d8903a6);
	  write_be32 (dso, rela->r_offset + 12, 0x4e800420);
	}
    } 
}

static int
ppc64_prelink_rela (struct prelink_info *info, GElf_Rela *rela,
		    GElf_Addr relaaddr)
{
  DSO *dso = info->dso;
  GElf_Addr value;

  if (GELF_R_TYPE (rela->r_info) == R_PPC64_NONE)
    return 0;
  else if (GELF_R_TYPE (rela->r_info) == R_PPC64_RELATIVE)
    {
      write_be64 (dso, rela->r_offset, rela->r_addend);
      return 0;
    }
  value = info->resolve (info, GELF_R_SYM (rela->r_info),
			 GELF_R_TYPE (rela->r_info));
  value += rela->r_addend;
  switch (GELF_R_TYPE (rela->r_info))    
    {
    case R_PPC64_GLOB_DAT:
    case R_PPC64_ADDR64:
    case R_PPC64_UADDR64:
      write_be64 (dso, rela->r_offset, value);
      break;
    case R_PPC64_ADDR32:
    case R_PPC64_UADDR32:
      write_be64 (dso, rela->r_offset, value);
      break;
    case R_PPC64_JMP_SLOT:
      ppc64_fixup_plt (dso, rela, value);
      break;
    case R_PPC64_ADDR16:
    case R_PPC64_UADDR16:
    case R_PPC64_ADDR16_LO:
      write_be16 (dso, rela->r_offset, value);
      break;
    case R_PPC64_ADDR16_HI:
      write_be16 (dso, rela->r_offset, value >> 16);
      break;
    case R_PPC64_ADDR16_HA:
      write_be16 (dso, rela->r_offset, (value + 0x8000) >> 16);
      break;
    case R_PPC64_ADDR16_HIGHER:
      write_be16 (dso, rela->r_offset, value >> 32);
      break;
    case R_PPC64_ADDR16_HIGHERA:
      write_be16 (dso, rela->r_offset, (value + 0x8000) >> 32);
      break;
    case R_PPC64_ADDR16_HIGHEST:
      write_be16 (dso, rela->r_offset, value >> 48);
      break;
    case R_PPC64_ADDR16_HIGHESTA:
      write_be16 (dso, rela->r_offset, (value + 0x8000) >> 48);
      break;
    case R_PPC64_ADDR16_LO_DS:
    case R_PPC64_ADDR16_DS:
      write_be16 (dso, rela->r_offset,
		  (value & 0xfffc) | read_ube16 (dso->rela->r_offset & 3));
      break;
    case R_PPC64_ADDR24:
      write_be32 (dso, rela->r_offset,
		  (value & 0x03fffffc)
		  | (read_ube32 (dso, rela->r_offset) & 0xfc000003));
      break;
    case R_PPC64_ADDR14:
      write_be32 (dso, rela->r_offset,
		  (value & 0xfffc)
		  | (read_ube32 (dso, rela->r_offset) & 0xffff0003));
      break;
    case R_PPC64_ADDR14_BRTAKEN:
    case R_PPC64_ADDR14_BRNTAKEN:
      write_be32 (dso, rela->r_offset,
		  (value & 0xfffc)
		  | (read_ube32 (dso, rela->r_offset) & 0xffdf0003)
		  | (((GELF_R_TYPE (rela->r_info) == R_PPC64_ADDR14_BRTAKEN)
		      ^ (value >> 10)) & 0x00200000));
      break;
    case R_PPC64_REL24:
      write_be32 (dso, rela->r_offset,
		  ((value - rela->r_offset) & 0x03fffffc)
		  | (read_ube32 (dso, rela->r_offset) & 0xfc000003));
      break;
    case R_PPC64_REL32:
      write_be32 (dso, rela->r_offset, value - rela->r_offset);
      break;
    case R_PPC64_COPY:
      if (dso->ehdr.e_type == ET_EXEC)
	/* COPY relocs are handled specially in generic code.  */
	return 0;
      error (0, 0, "%s: R_PPC64_COPY reloc in shared library?", dso->filename);
      return 1;
    default:
      error (0, 0, "%s: Unknown ppc relocation type %d", dso->filename,
	     (int) GELF_R_TYPE (rela->r_info));
      return 1;
    }
  return 0;
}

static int
ppc64_apply_conflict_rela (struct prelink_info *info, GElf_Rela *rela,
			  char *buf)
{
  switch (GELF_R_TYPE (rela->r_info))    
    {
    case R_PPC64_ADDR64:
    case R_PPC64_UADDR64:
      buf_write_be64 (buf, rela->r_addend);
      break;
    case R_PPC64_ADDR32:
    case R_PPC64_UADDR32:
      buf_write_be32 (buf, rela->r_addend);
      break;
    case R_PPC64_ADDR16:
    case R_PPC64_UADDR16:
      buf_write_be16 (buf, rela->r_addend);
      break;
    default:
      abort ();
    }
  return 0;
}

static int
ppc64_apply_rel (struct prelink_info *info, GElf_Rel *rel, char *buf)
{
  error (0, 0, "%s: PowerPC64 doesn't support REL relocs", info->dso->filename);
  return 1;
}

static int
ppc64_apply_rela (struct prelink_info *info, GElf_Rela *rela, char *buf)
{
  GElf_Addr value;

  value = info->resolve (info, GELF_R_SYM (rela->r_info),
			 GELF_R_TYPE (rela->r_info));
  value += rela->r_addend;
  switch (GELF_R_TYPE (rela->r_info))    
    {
    case R_PPC64_NONE:
      break;
    case R_PPC64_GLOB_DAT:
    case R_PPC64_ADDR64:
    case R_PPC64_UADDR64:
      buf_write_be64 (buf, value);
      break;
    case R_PPC64_ADDR32:
    case R_PPC64_UADDR32:
      buf_write_be32 (buf, value);
      break;
    case R_PPC64_ADDR16_HA:
      value += 0x8000;
      /* FALLTHROUGH  */
    case R_PPC64_ADDR16_HI:
      value = value >> 16;
      /* FALLTHROUGH  */
    case R_PPC64_ADDR16:
    case R_PPC64_UADDR16:
    case R_PPC64_ADDR16_LO:
      buf_write_be16 (buf, value);
      break;
    case R_PPC64_ADDR16_HIGHERA:
      value += 0x8000;
      /* FALLTHROUGH  */
    case R_PPC64_ADDR16_HIGHERA:
      buf_write_be16 (buf, value >> 32);
      break;
    case R_PPC64_ADDR16_HIGHESTA:
      value += 0x8000;
      /* FALLTHROUGH  */
    case R_PPC64_ADDR16_HIGHESTA:
      buf_write_be16 (buf, value >> 48);
      break;
    case R_PPC64_ADDR16_LO_DS:
    case R_PPC64_ADDR16_DS:
      buf_write_be16 (buf, (value & 0xfffc)
			   | (buf_read_ube16 (buf) & 3));
      break;
    case R_PPC64_ADDR24:
      buf_write_be32 (buf, (value & 0x03fffffc)
			   | (buf_read_ube32 (buf) & 0xfc000003));
      break;
    case R_PPC64_ADDR14:
      buf_write_be32 (buf, (value & 0xfffc)
			   | (buf_read_ube32 (buf) & 0xffff0003));
      break;
    case R_PPC64_ADDR14_BRTAKEN:
    case R_PPC64_ADDR14_BRNTAKEN:
      buf_write_be32 (buf, (value & 0xfffc)
			   | (buf_read_ube32 (buf) & 0xffdf0003)
			   | (((GELF_R_TYPE (rela->r_info)
				== R_PPC64_ADDR14_BRTAKEN)
			       ^ (value >> 10)) & 0x00200000));
      break;
    case R_PPC64_REL24:
      buf_write_be32 (buf, ((value - rela->r_offset) & 0x03fffffc)
			   | (buf_read_ube32 (buf) & 0xfc000003));
      break;
    case R_PPC64_REL32:
      buf_write_be32 (buf, value - rela->r_offset);
      break;
    case R_PPC64_RELATIVE:
      error (0, 0, "%s: R_PPC64_RELATIVE in ET_EXEC object?",
	     info->dso->filename);
      return 1;
    default:
      return 1;
    }
  return 0;
}

static int
ppc64_prelink_conflict_rel (DSO *dso, struct prelink_info *info,
			    GElf_Rel *rel, GElf_Addr reladdr)
{
  error (0, 0, "%s: PowerPC64 doesn't support REL relocs", dso->filename);
  return 1;
}

static int
ppc64_prelink_conflict_rela (DSO *dso, struct prelink_info *info,
			     GElf_Rela *rela, GElf_Addr relaaddr)
{
  GElf_Addr value;
  struct prelink_conflict *conflict;
  GElf_Rela *ret;
  int r_type;

  if (GELF_R_TYPE (rela->r_info) == R_PPC64_RELATIVE
      || GELF_R_TYPE (rela->r_info) == R_PPC64_NONE)
    /* Fast path: nothing to do.  */
    return 0;
  conflict = prelink_conflict (info, GELF_R_SYM (rela->r_info),
			       GELF_R_TYPE (rela->r_info));
  if (conflict == NULL)
    return 0;
  value = conflict_lookup_value (conflict);
  ret = prelink_conflict_add_rela (info);
  if (ret == NULL)
    return 1;
  ret->r_offset = rela->r_offset;
  value += rela->r_addend;
  r_type = GELF_R_TYPE (rela->r_info);
  switch (r_type)    
    {
    case R_PPC64_GLOB_DAT:
      r_type = R_PPC64_ADDR64;
      break;
    case R_PPC64_ADDR64:
    case R_PPC64_UADDR64:
    case R_PPC64_JMP_SLOT:
      break;
    case R_PPC64_ADDR32:
    case R_PPC64_UADDR32:
      value = (Elf32_Sword) value;
      break;
    case R_PPC64_ADDR16_HA:
      value += 0x8000;
      /* FALLTHROUGH  */
    case R_PPC64_ADDR16_HI:
      value = value >> 16;
      /* FALLTHROUGH  */
    case R_PPC64_ADDR16:
    case R_PPC64_UADDR16:
    case R_PPC64_ADDR16_LO:
      if (r_type != R_PPC64_UADDR16)
	r_type = R_PPC64_ADDR16;
      value = ((value & 0xffff) ^ 0x8000) - 0x8000;
      break;
    case R_PPC64_ADDR16_HIGHERA:
      value += 0x8000;
      /* FALLTHROUGH  */
    case R_PPC64_ADDR16_HIGHER:
      r_type = R_PPC64_ADDR16;
      value = (((value >> 32) & 0xffff) ^ 0x8000) - 0x8000;
      break;
    case R_PPC64_ADDR16_HIGHESTA:
      value += 0x8000;
      /* FALLTHROUGH  */
    case R_PPC64_ADDR16_HIGHEST:
      r_type = R_PPC64_ADDR16;
      value = ((Elf64_Sxword) value) >> 48;
      break;
    case R_PPC64_ADDR16_LO_DS:
    case R_PPC64_ADDR16_DS:
      r_type = R_PPC64_ADDR16;
      value = ((value & 0xffff) ^ 0x8000) - 0x8000;
      value |= read_ube16 (dso, rela->r_offset) & 3;
      break;
    case R_PPC64_ADDR24:
      r_type = R_PPC64_ADDR32;
      value = (value & 0x03fffffc)
	      | (read_ube32 (dso, rela->r_offset) & 0xfc000003);
      value = (Elf32_Sword) value;
      break;
    case R_PPC64_ADDR14:
      r_type = R_PPC64_ADDR32;
      value = (value & 0xfffc)
	      | (read_ube32 (dso, rela->r_offset) & 0xffff0003);
      value = (Elf32_Sword) value;
      break;
    case R_PPC64_ADDR14_BRTAKEN:
    case R_PPC64_ADDR14_BRNTAKEN:
      r_type = R_PPC64_ADDR32;
      value = (value & 0xfffc)
	      | (read_ube32 (dso, rela->r_offset) & 0xffdf0003)
	      | (((r_type == R_PPC64_ADDR14_BRTAKEN)
		  ^ (value >> 10)) & 0x00200000);
      value = (Elf32_Sword) value;
      break;
    case R_PPC64_REL24:
      r_type = R_PPC64_ADDR32;
      value = ((value - rela->r_offset) & 0x03fffffc)
	      | (read_ube32 (dso, rela->r_offset) & 0xfc000003);
      value = (Elf32_Sword) value;
      break;
    case R_PPC64_REL32:
      r_type = R_PPC64_ADDR32;
      value -= rela->r_offset;
      value = (Elf32_Sword) value;
      break;
    default:
      error (0, 0, "%s: Unknown PowerPC64 relocation type %d", dso->filename,
	     r_type);
      return 1;
    }
  ret->r_info = GELF_R_INFO (0, r_type);
  ret->r_addend = value;
  return 0;
}

static int
ppc64_rel_to_rela (DSO *dso, GElf_Rel *rel, GElf_Rela *rela)
{
  error (0, 0, "%s: PowerPC64 doesn't support REL relocs", dso->filename);
  return 1;
}

static int
ppc64_need_rel_to_rela (DSO *dso, int first, int last)
{
  return 0;
}

static int
ppc64_arch_prelink (DSO *dso)
{
  Elf32_Addr plt = dso->info[DT_PLTGOT];

  if (plt)
    {
      Elf32_Word count = dso->info[DT_PLTRELSZ] / sizeof (Elf32_Rela);
      Elf32_Addr data;

      data = plt + (18 + 2 * count
		    + (count > 8192 ? (count - 8192) * 2 : 0)) * 4;

      /* addis %r11, %r11, %hi(data)
	 lwz %r11, %r11, %lo(data)
	 mtctr %r11
	 bctr  */
      write_be32 (dso, plt,  0x3d6b0000 | (((data + 0x8000) >> 16) & 0xffff));
      write_be32 (dso, plt + 4, 0x816b0000 | (data & 0xffff));
      write_be32 (dso, plt + 8, 0x7d6903a6);
      write_be32 (dso, plt + 12, 0x4e800420);
    }
  return 0;
}

static int
ppc64_undo_prelink_rela (DSO *dso, GElf_Rela *rela, GElf_Addr relaaddr)
{
  switch (GELF_R_TYPE (rela->r_info))
    {
    case R_PPC64_NONE:
      return 0;
    case R_PPC64_RELATIVE:
    case R_PPC64_GLOB_DAT:
    case R_PPC64_ADDR64:
    case R_PPC64_UADDR64:
      write_be64 (dso, rela->r_offset, 0);
      break;
    case R_PPC64_ADDR32:
    case R_PPC64_UADDR32:
    case R_PPC64_REL32:
      write_be32 (dso, rela->r_offset, 0);
      break;
    case R_PPC64_JMP_SLOT:
      /* .plt section will become SHT_NOBITS.  */
      return 0;
    case R_PPC64_ADDR16:
    case R_PPC64_UADDR16:
    case R_PPC64_ADDR16_LO:
    case R_PPC64_ADDR16_HI:
    case R_PPC64_ADDR16_HA:
    case R_PPC64_ADDR16_HIGHER:
    case R_PPC64_ADDR16_HIGHERA:
    case R_PPC64_ADDR16_HIGHEST:
    case R_PPC64_ADDR16_HIGHESTA:
    case R_PPC64_ADDR16_LO_DS:
    case R_PPC64_ADDR16_DS:
      write_be16 (dso, rela->r_offset, 0);
      break;
    case R_PPC64_ADDR24:
    case R_PPC64_REL24:
      write_be32 (dso, rela->r_offset,
		  read_ube32 (dso, rela->r_offset) & 0xfc000003);
      break;
    case R_PPC64_ADDR14:
      write_be32 (dso, rela->r_offset,
		  read_ube32 (dso, rela->r_offset) & 0xffff0003);
      break;
    case R_PPC64_ADDR14_BRTAKEN:
    case R_PPC64_ADDR14_BRNTAKEN:
      write_be32 (dso, rela->r_offset,
		  read_ube32 (dso, rela->r_offset) & 0xffdf0003);
      break;
    case R_PPC64_COPY:
      if (dso->ehdr.e_type == ET_EXEC)
	/* COPY relocs are handled specially in generic code.  */
	return 0;
      error (0, 0, "%s: R_PPC64_COPY reloc in shared library?", dso->filename);
      return 1;
    default:
      error (0, 0, "%s: Unknown ppc relocation type %d", dso->filename,
	     (int) GELF_R_TYPE (rela->r_info));
      return 1;
    }
  return 0;
}
static int
ppc64_reloc_size (int reloc_type)
{
  switch (reloc_type)
    {
    case R_PPC64_ADDR16:
    case R_PPC64_UADDR16:
    case R_PPC64_ADDR16_LO:
    case R_PPC64_ADDR16_HA:
    case R_PPC64_ADDR16_HI:
    case R_PPC64_ADDR16_LO_DS:
    case R_PPC64_ADDR16_DS:
    case R_PPC64_ADDR16_HIGHER:
    case R_PPC64_ADDR16_HIGHERA:
    case R_PPC64_ADDR16_HIGHEST:
    case R_PPC64_ADDR16_HIGHESTA:
      return 2;
    case R_PPC64_GLOB_DAT:
    case R_PPC64_ADDR64:
    case R_PPC64_UADDR64:
      return 8;
    default:
      break;
    }
  return 4;
}

static int
ppc64_reloc_class (int reloc_type)
{
  switch (reloc_type)
    {
    case R_PPC64_COPY: return RTYPE_CLASS_COPY;
    case R_PPC64_JMP_SLOT: return RTYPE_CLASS_PLT;
    default: return RTYPE_CLASS_VALID;
    }
}

PL_ARCH = {
  .class = ELFCLASS64,
  .machine = EM_PPC64,
  .alternate_machine = { EM_NONE },
  .R_JMP_SLOT = R_PPC64_JMP_SLOT,
  .R_COPY = R_PPC64_COPY,
  .R_RELATIVE = R_PPC64_RELATIVE,
  .dynamic_linker = "/lib64/ld64.so.1",
  .adjust_dyn = ppc64_adjust_dyn,
  .adjust_rel = ppc64_adjust_rel,
  .adjust_rela = ppc64_adjust_rela,
  .prelink_rel = ppc64_prelink_rel,
  .prelink_rela = ppc64_prelink_rela,
  .prelink_conflict_rel = ppc64_prelink_conflict_rel,
  .prelink_conflict_rela = ppc64_prelink_conflict_rela,
  .apply_conflict_rela = ppc64_apply_conflict_rela,
  .apply_rel = ppc64_apply_rel,
  .apply_rela = ppc64_apply_rela,
  .rel_to_rela = ppc64_rel_to_rela,
  .need_rel_to_rela = ppc64_need_rel_to_rela,
  .reloc_size = ppc64_reloc_size,
  .reloc_class = ppc64_reloc_class,
  .max_reloc_size = 8,
  .arch_prelink = ppc64_arch_prelink,
  .undo_prelink_rela = ppc64_undo_prelink_rela,
  /* Although TASK_UNMAPPED_BASE is 0x8000000000, we leave some
     area so that mmap of /etc/ld.so.cache and ld.so's malloc
     does not take some library's VA slot.
     Also, if this guard area isn't too small, typically
     even dlopened libraries will get the slots they desire.  */
  .mmap_base = 0x8001000000LL,
  .mmap_end =  0x8100000000LL,
  .max_page_size = 0x10000,
  .page_size = 0x1000
};
