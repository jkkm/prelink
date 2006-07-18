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

struct prelink_conflict *
prelink_conflict (struct prelink_info *info, GElf_Word r_sym,
		  int reloc_type)
{
  GElf_Word symoff = info->symtab_start + r_sym * info->symtab_entsize;
  struct prelink_conflict *conflict;
  int reloc_class = info->dso->arch->reloc_class (reloc_type);

  for (conflict = info->curconflicts; conflict; conflict = conflict->next)
    if (conflict->symoff == symoff && conflict->reloc_class == reloc_class)
      {
	conflict->used = 1;
	return conflict;
      }

  return NULL;
}

GElf_Rela *
prelink_conflict_add_rela (struct prelink_info *info)
{
  GElf_Rela *ret;

  if (info->conflict_rela_alloced == info->conflict_rela_size)
    {
      info->conflict_rela_alloced += 10;
      info->conflict_rela = realloc (info->conflict_rela,
				     info->conflict_rela_alloced
				     * sizeof (GElf_Rela));
      if (info->conflict_rela == NULL)
	{
	  error (0, ENOMEM, "Could not build .gnu.conflict section memory image");
	  return NULL;
	}
    }
  ret = info->conflict_rela + info->conflict_rela_size++;
  ret->r_offset = 0;
  ret->r_info = 0;
  ret->r_addend = 0;
  return ret;
}

static int
prelink_conflict_rel (DSO *dso, int n, struct prelink_info *info)
{
  Elf_Data *data = NULL;
  Elf_Scn *scn = elf_getscn (dso->elf, n);
  GElf_Rel rel;
  int sec, ndx, maxndx;

  while ((data = elf_getdata (scn, data)) != NULL)
    {
      GElf_Addr addr = dso->shdr[n].sh_addr + data->d_off;

      maxndx = data->d_size / dso->shdr[n].sh_entsize;
      for (ndx = 0; ndx < maxndx;
	   ++ndx, addr += dso->shdr[n].sh_entsize)
	{
	  gelfx_getrel (dso->elf, data, ndx, &rel);
	  sec = addr_to_sec (dso, rel.r_offset);
	  if (sec == -1)
	    continue;

	  if (dso->arch->prelink_conflict_rel (dso, info, &rel, addr))
	    return 1;
	}
    }
  return 0;
}

static int
prelink_conflict_rela (DSO *dso, int n, struct prelink_info *info)
{
  Elf_Data *data = NULL;
  Elf_Scn *scn = elf_getscn (dso->elf, n);
  GElf_Rela rela;
  int sec, ndx, maxndx;

  while ((data = elf_getdata (scn, data)) != NULL)
    {
      GElf_Addr addr = dso->shdr[n].sh_addr + data->d_off;
      
      maxndx = data->d_size / dso->shdr[n].sh_entsize;
      for (ndx = 0; ndx < maxndx;
	   ++ndx, addr += dso->shdr[n].sh_entsize)
	{
	  gelfx_getrela (dso->elf, data, ndx, &rela);
	  sec = addr_to_sec (dso, rela.r_offset);
	  if (sec == -1)
	    continue;

	  if (dso->arch->prelink_conflict_rela (dso, info, &rela, addr))
	    return 1;
	}
    }
  return 0;
}

struct copy_relocs
{
  GElf_Rela *rela;
  int alloced;
  int count;
};

static int
prelink_add_copy_rel (DSO *dso, int n, GElf_Rel *rel, struct copy_relocs *cr)
{
  Elf_Data *data = NULL;
  int symsec = dso->shdr[n].sh_link;
  Elf_Scn *scn = elf_getscn (dso->elf, symsec);
  GElf_Sym sym;
  size_t entsize = dso->shdr[symsec].sh_entsize;
  off_t off = GELF_R_SYM (rel->r_info) * entsize;
    
  while ((data = elf_getdata (scn, data)) != NULL)
    {
      if (data->d_off <= off &&
	  data->d_off + data->d_size >= off + entsize)
	{
	  gelfx_getsym (dso->elf, data, (off - data->d_off) / entsize, &sym);
	  if (sym.st_size == 0)
	    {
	      error (0, 0, "%s: Copy reloc against symbol with zero size",
		     dso->filename);
	      return 1;
	    }

	  if (cr->alloced == cr->count)
	    {
	      cr->alloced += 10;
	      cr->rela = realloc (cr->rela, cr->alloced * sizeof (GElf_Rela));
	      if (cr->rela == NULL)
		{
		  error (0, ENOMEM, "%s: Could not build list of COPY relocs",
			 dso->filename);
		  return 1;
		}
	    }
	  cr->rela[cr->count].r_offset = rel->r_offset;
	  cr->rela[cr->count].r_info = rel->r_info;
	  cr->rela[cr->count].r_addend = sym.st_size;
	  ++cr->count;
	  return 0;
	}
    }

  error (0, 0, "%s: Copy reloc against unknown symbol", dso->filename);
  return 1;
}

static int
prelink_find_copy_rel (DSO *dso, int n, struct copy_relocs *cr)
{
  Elf_Data *data = NULL;
  Elf_Scn *scn = elf_getscn (dso->elf, n);
  GElf_Rel rel;
  int sec, ndx, maxndx;

  while ((data = elf_getdata (scn, data)) != NULL)
    {
      maxndx = data->d_size / dso->shdr[n].sh_entsize;
      for (ndx = 0; ndx < maxndx; ++ndx)
	{
	  gelfx_getrel (dso->elf, data, ndx, &rel);
	  sec = addr_to_sec (dso, rel.r_offset);
	  if (sec == -1)
	    continue;

	  if (GELF_R_TYPE (rel.r_info) == dso->arch->R_COPY
	      && prelink_add_copy_rel (dso, n, &rel, cr))
	    return 1;
	}
    }
  return 0;
}

static int
prelink_find_copy_rela (DSO *dso, int n, struct copy_relocs *cr)
{
  Elf_Data *data = NULL;
  Elf_Scn *scn = elf_getscn (dso->elf, n);
  union {
    GElf_Rel rel;
    GElf_Rela rela;
  } u;
  int sec, ndx, maxndx;

  while ((data = elf_getdata (scn, data)) != NULL)
    {
      maxndx = data->d_size / dso->shdr[n].sh_entsize;
      for (ndx = 0; ndx < maxndx; ++ndx)
	{
	  gelfx_getrela (dso->elf, data, ndx, &u.rela);
	  sec = addr_to_sec (dso, u.rela.r_offset);
	  if (sec == -1)
	    continue;

	  if (GELF_R_TYPE (u.rela.r_info) == dso->arch->R_COPY)
	    {
	      if (u.rela.r_addend != 0)
		{
		  error (0, 0, "%s: COPY reloc with non-zero addend?",
			 dso->filename);
		  return 1;
		}
	      if (prelink_add_copy_rel (dso, n, &u.rel, cr))
		return 1;
	    }
	}
    }
  return 0;
}

struct readonly_adjust
{
  off_t basemove_adjust;
  GElf_Addr basemove_end;
  int moveend;
  int move2;
};

static int
find_readonly_space (DSO *dso, GElf_Shdr *add, GElf_Ehdr *ehdr,
		     GElf_Phdr *phdr, GElf_Shdr *shdr, 
		     struct readonly_adjust *adjust)
{
  int i, j;
  GElf_Addr addr;

  if (add->sh_addr)
    {
      /* Prefer the current address if possible.  */
      for (i = 0; i < ehdr->e_phnum; ++i)
	if (phdr[i].p_type == PT_LOAD
	    && (phdr[i].p_flags & (PF_R | PF_W)) == PF_R
	    && phdr[i].p_vaddr <= add->sh_addr
	    && phdr[i].p_vaddr + phdr[i].p_filesz
	       >= add->sh_addr + add->sh_size)
	  break;

      if (i < ehdr->e_phnum)
	for (j = 1; j < ehdr->e_shnum; ++j)
	  if ((shdr[j].sh_flags & SHF_ALLOC)
	      && shdr[j].sh_addr >= add->sh_addr)
	    {
	      if (shdr[j].sh_addr >= add->sh_addr + add->sh_size)
		{
		  memmove (&shdr[j + 1], &shdr[j],
			   (ehdr->e_shnum - j) * sizeof (GElf_Shdr));
		  shdr[j] = *add;
		  shdr[j].sh_offset = (shdr[j].sh_addr - phdr[i].p_vaddr)
				       + phdr[i].p_offset;
		  ++ehdr->e_shnum;
		  return j;
		}
	      break;
	    }
    }

  for (i = 0; i < ehdr->e_phnum; ++i)
    if (phdr[i].p_type == PT_LOAD
	&& (phdr[i].p_flags & (PF_R | PF_W)) == PF_R)
      {
	GElf_Addr start = phdr[i].p_vaddr;
	int after = 0, min;

	if (phdr[i].p_offset < ehdr->e_phoff)
	  start += ehdr->e_phoff
		   + (ehdr->e_phnum + 1) * ehdr->e_phentsize
		   - phdr[i].p_offset;
	start = (start + add->sh_addralign - 1) & ~(add->sh_addralign - 1);
	for (j = 1; j < ehdr->e_shnum; ++j)
	  if ((shdr[j].sh_flags & SHF_ALLOC)
	      && shdr[j].sh_addr >= phdr[i].p_vaddr
	      && shdr[j].sh_addr + shdr[j].sh_size
		 <= phdr[i].p_vaddr + phdr[i].p_filesz
	      && start + add->sh_size > shdr[j].sh_addr)
	    {
	      start = shdr[j].sh_addr + shdr[j].sh_size;
	      start = (start + add->sh_addralign - 1)
		      & ~(add->sh_addralign - 1);
	      after = j;
	    }

	min = -1;
	for (j = i + 1; j < ehdr->e_phnum; ++j)
	  if (phdr[j].p_offset >= phdr[i].p_offset + phdr[i].p_filesz
	      && (min == -1 || phdr[min].p_offset > phdr[j].p_offset))
	    min = j;

	if (start + add->sh_size <= phdr[i].p_vaddr + phdr[i].p_filesz
	    || (phdr[i].p_filesz == phdr[i].p_memsz
		&& (min == -1
		    || start + add->sh_size - phdr[i].p_vaddr
		       <= phdr[min].p_offset)))
	  {
	    if (after == 0)
	      {
		for (j = 1; j < ehdr->e_shnum; ++j)
		  if (! (shdr[j].sh_flags & SHF_ALLOC)
		      || shdr[j].sh_addr > phdr[i].p_vaddr)
		    after = j - 1;
	      }
	    memmove (&shdr[after + 2], &shdr[after + 1],
		     (ehdr->e_shnum - after - 1) * sizeof (GElf_Shdr));
	    shdr[after + 1] = *add;
	    shdr[after + 1].sh_addr = start;
	    shdr[after + 1].sh_offset = (start - phdr[i].p_vaddr)
					 + phdr[i].p_offset;
	    ++ehdr->e_shnum;
	    if (start + add->sh_size > phdr[i].p_vaddr + phdr[i].p_filesz)
	      {
		adjust_nonalloc (dso, ehdr, shdr, 0, 0,
				 start + add->sh_size - phdr[i].p_vaddr
				 - phdr[i].p_filesz);
		phdr[i].p_filesz = start + add->sh_size - phdr[i].p_vaddr;
		phdr[i].p_memsz = phdr[i].p_filesz;
	      }
	    return after + 1;
	  }
      }

  /* If SHT_NOBITS sections are small, just extend the last PT_LOAD
     segment.  Small enough here means that the whole .bss fits into
     the same CPU page as the alloced part of it.  */
  for (i = -1, j = 0; j < ehdr->e_phnum; ++j)
    if (phdr[j].p_type == PT_LOAD)
      i = j;
  if (phdr[i].p_filesz
      && phdr[i].p_filesz <= phdr[i].p_memsz
      && !(((phdr[i].p_vaddr + phdr[i].p_memsz - 1)
	    ^ (phdr[i].p_vaddr + phdr[i].p_filesz - 1)) & ~(GElf_Addr) 4095))
    {
      for (j = 1; j < ehdr->e_shnum; ++j)
	{
	  if (!(shdr[j].sh_flags & (SHF_ALLOC | SHF_WRITE | SHF_ALLOC)))
	    break;
	  if (shdr[j].sh_type == SHT_NOBITS
	      && shdr[j].sh_addr >= phdr[i].p_vaddr)
	    shdr[j].sh_type = SHT_PROGBITS;
	}

      memmove (&shdr[j + 1], &shdr[j],
	       (ehdr->e_shnum - j) * sizeof (GElf_Shdr));
      shdr[j] = *add;
      shdr[j].sh_addr = (shdr[j - 1].sh_addr + shdr[j - 1].sh_size
			 + add->sh_addralign - 1) & ~(add->sh_addralign - 1);
      shdr[j].sh_offset = (shdr[j].sh_addr - phdr[i].p_vaddr)
			  + phdr[i].p_offset;
      ++ehdr->e_shnum;
      phdr[i].p_filesz = shdr[j].sh_addr + add->sh_size - phdr[i].p_vaddr;
      phdr[i].p_memsz = phdr[i].p_filesz;
      adjust_nonalloc (dso, ehdr, shdr, 0, 0, phdr[i].p_offset
		       + phdr[i].p_filesz - shdr[j + 1].sh_offset);
      return j;
    }

  /* See if we can decrease binary's base VMA and thus gain space.
     This trick is mainly useful for IA-32.  */
  for (i = 0; i < ehdr->e_phnum; ++i)
    if (phdr[i].p_type == PT_LOAD)
      break;

  addr = (add->sh_size + add->sh_addralign - 1 + phdr[i].p_align - 1)
	 & ~(phdr[i].p_align - 1);
  if (phdr[i].p_align <= 4096
      && phdr[i].p_flags == (PF_R | PF_X)
      && phdr[i].p_filesz == phdr[i].p_memsz
      && phdr[i].p_vaddr - addr
      && ! (((phdr[i].p_vaddr - addr) ^ phdr[i].p_vaddr)
	    & ~(phdr[i].p_align * 256 - 1)))
    {
      int moveend;
      if (! adjust->basemove_end)
	{
	  for (moveend = 1; moveend < ehdr->e_shnum; ++moveend)
	    if (strcmp (strptr (dso, ehdr->e_shstrndx,
				shdr[moveend].sh_name), ".interp")
		&& shdr[moveend].sh_type != SHT_NOTE)
	      break;
	  if (moveend < ehdr->e_shnum && moveend > 1)
	    {
	      adjust->basemove_end = shdr[moveend].sh_addr;
	      adjust->moveend = moveend;
	    }
	}
      else
        moveend = adjust->moveend;
      if (moveend < ehdr->e_shnum && moveend > 1
	  && (shdr[moveend].sh_flags & (SHF_ALLOC | SHF_WRITE)))
	{
	  int k = moveend;

	  if (add->sh_addr && ! adjust->move2
	      && phdr[i].p_vaddr <= add->sh_addr
	      && phdr[i].p_vaddr + phdr[i].p_filesz > add->sh_addr)
	    {
	      for (k = moveend; k < ehdr->e_shnum; ++k)
		{
		  if (! (shdr[k].sh_flags & (SHF_ALLOC | SHF_WRITE)))
		    {
		      k = ehdr->e_shnum;
		      break;
		    }

		  if (shdr[k].sh_addr > add->sh_addr)
		    break;

		  switch (shdr[k].sh_type)
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
		      break;
		    default:
		      k = ehdr->e_shnum;
		      break;
		    }
		}

	      if (k < ehdr->e_shnum)
	        {
		  GElf_Addr a;

		  a = shdr[k].sh_addr - add->sh_addr;
		  assert (add->sh_addralign <= phdr[i].p_align);
		  a = (add->sh_size - a + phdr[i].p_align - 1)
		      & ~(phdr[i].p_align - 1);
		  if (a < addr)
		    {
		      adjust->move2 = 1;
		      addr = a;
		    }
		  else
		    k = moveend;
	        }
	      else
	        k = moveend;
	    }

	  for (j = 1; j < k; ++j)
	    shdr[j].sh_addr -= addr;
	  phdr[i].p_vaddr -= addr;
	  phdr[i].p_paddr -= addr;
	  phdr[i].p_filesz += addr;
	  phdr[i].p_memsz += addr;
	  for (j = 0; j < ehdr->e_phnum; ++j)
	    {
	      if (j == i)
		continue;
	      if (phdr[j].p_vaddr
		  < adjust->basemove_end - adjust->basemove_adjust)
		{
		  phdr[j].p_vaddr -= addr;
		  phdr[j].p_paddr -= addr;
		}
	      else
		phdr[j].p_offset += addr;
	    }
	  adjust->basemove_adjust += addr;
	  ++ehdr->e_shnum;
	  adjust_nonalloc (dso, ehdr, shdr, 0, 0, addr);
	  memmove (&shdr[k + 1], &shdr[k],
		     (ehdr->e_shnum - k) * sizeof (GElf_Shdr));
	  shdr[k] = *add;
	  if (k == moveend)
	    {
	      addr = shdr[k - 1].sh_addr + shdr[k - 1].sh_size;
	      addr = (addr + add->sh_addralign - 1) & ~(add->sh_addralign - 1);
	    }
	  else
	    {
	      addr = (shdr[k + 1].sh_addr - add->sh_size)
		     & ~(add->sh_addralign - 1);
	    }
	  
	  shdr[k].sh_addr = addr;
	  shdr[k].sh_offset = (addr - phdr[i].p_vaddr) + phdr[i].p_offset;
	  return k;
	}
    }

  /* We have to create new PT_LOAD if at all possible.  */
  addr = ehdr->e_phoff + (ehdr->e_phnum + 1) * ehdr->e_phentsize;
  for (i = 1; i < ehdr->e_shnum; ++i)
    {
      if (addr > shdr[i].sh_offset)
	{
	  error (0, 0, "%s: No space in ELF segment table to add new ELF segment",
		 dso->filename);
	  return 0;
	}
    }

  for (i = 0, j = 0; i < ehdr->e_phnum; ++i)
    if (phdr[i].p_type == PT_LOAD)
      j = i;

  memmove (&phdr[j + 2], &phdr[j + 1],
	   (ehdr->e_phnum - j - 1) * sizeof (GElf_Phdr));
  ++ehdr->e_phnum;
  phdr[++j].p_type = PT_LOAD;
  phdr[j].p_offset = phdr[j - 1].p_offset + phdr[j - 1].p_filesz;
  phdr[j].p_offset = (phdr[j].p_offset + add->sh_addralign - 1)
		      & ~(add->sh_addralign - 1);
  phdr[j].p_align = phdr[j - 1].p_align;
  phdr[j].p_vaddr = phdr[j - 1].p_vaddr + phdr[j - 1].p_memsz;
  phdr[j].p_vaddr += (2 * phdr[j].p_align - 1);
  phdr[j].p_vaddr &= ~(phdr[j].p_align - 1);
  phdr[j].p_vaddr += (phdr[j].p_offset & (phdr[j].p_align - 1));
  phdr[j].p_paddr = phdr[j].p_vaddr;
  phdr[j].p_flags = PF_R;
  phdr[j].p_filesz = add->sh_size;
  phdr[j].p_memsz = add->sh_size;
  for (i = 1; i < ehdr->e_shnum; ++i)
    if (! (shdr[i].sh_flags & (SHF_WRITE | SHF_ALLOC | SHF_EXECINSTR)))
      break;
  assert (i < ehdr->e_shnum);
  memmove (&shdr[i + 1], &shdr[i],
	   (ehdr->e_shnum - i) * sizeof (GElf_Shdr));
  shdr[i] = *add;
  shdr[i].sh_addr = phdr[j].p_vaddr;
  shdr[i].sh_offset = phdr[j].p_offset;
  ++ehdr->e_shnum;
  adjust_nonalloc (dso, ehdr, shdr, 0, 0, 
		   phdr[j].p_offset + phdr[j].p_filesz - phdr[j - 1].p_offset
		   - phdr[j - 1].p_filesz);
  return i;
}

static int
update_dynamic_tags (DSO *dso, GElf_Shdr *old_shdr, struct section_move *move)
{
  int i, j;
  
  for (i = 1; i < dso->ehdr.e_shnum; ++i)
    {
      j = move->new_to_old[i];
      if (j == -1)
	continue;
      if ((dynamic_info_is_set (dso, DT_HASH)
	   && dso->info[DT_HASH] == old_shdr[j].sh_addr
	   && set_dynamic (dso, DT_HASH, dso->shdr[i].sh_addr, 1))
	  || (dynamic_info_is_set (dso, DT_SYMTAB)
	      && dso->info[DT_SYMTAB] == old_shdr[j].sh_addr
	      && set_dynamic (dso, DT_SYMTAB, dso->shdr[i].sh_addr, 1))
	  || (dynamic_info_is_set (dso, DT_STRTAB)
	      && dso->info[DT_STRTAB] == old_shdr[j].sh_addr
	      && set_dynamic (dso, DT_STRTAB, dso->shdr[i].sh_addr, 1))
	  || (dynamic_info_is_set (dso, DT_VERDEF_BIT)
	      && dso->info_DT_VERDEF == old_shdr[j].sh_addr
	      && set_dynamic (dso, DT_VERDEF, dso->shdr[i].sh_addr, 1))
	  || (dynamic_info_is_set (dso, DT_VERNEED_BIT)
	      && dso->info_DT_VERNEED == old_shdr[j].sh_addr
	      && set_dynamic (dso, DT_VERNEED, dso->shdr[i].sh_addr, 1)) 
	  || (dynamic_info_is_set (dso, DT_VERSYM_BIT)
	      && dso->info_DT_VERSYM == old_shdr[j].sh_addr
	      && set_dynamic (dso, DT_VERSYM, dso->shdr[i].sh_addr, 1)))
	return 1;
    }

  return 0;
}

static int
rela_cmp (const void *A, const void *B)
{
  GElf_Rela *a = (GElf_Rela *)A;
  GElf_Rela *b = (GElf_Rela *)B;

  if (a->r_offset < b->r_offset)
    return -1;
  if (a->r_offset > b->r_offset)
    return 1;
  return 0;
}

int
get_relocated_mem (struct prelink_info *info, DSO *dso, GElf_Addr addr,
		   char *buf, GElf_Word size)
{
  int sec = addr_to_sec (dso, addr), j;
  Elf_Scn *scn;
  Elf_Data *data;
  off_t off;

  if (sec == -1)
    return 1;

  memset (buf, 0, size);
  if (dso->shdr[sec].sh_type != SHT_NOBITS)
    {
      scn = elf_getscn (dso->elf, sec);
      data = NULL;
      off = addr - dso->shdr[sec].sh_addr;
      while ((data = elf_rawdata (scn, data)) != NULL)
	{
	  if (data->d_off < off + size
	      && data->d_off + data->d_size > off)
	    {
	      off_t off2 = off - data->d_off;
	      size_t len = size;

	      if (off2 < 0)
		{
		  len += off2;
		  off2 = 0;
		}
	      if (off2 + len > data->d_size)
		len = data->d_size - off2;
	      assert (off2 + len <= data->d_size);
	      assert (len <= size);
	      memcpy (buf + off2 - off, data->d_buf + off2, len);
	    }
	}
    }

  if (info->dso != dso)
    {
      /* This is tricky. We need to apply any conflicts
	 against memory area which we've copied to the COPY
	 reloc offset.  */
      for (j = 0; j < info->conflict_rela_size; ++j)
	{
	  int reloc_type, reloc_size;
	  off_t off;

	  if (info->conflict_rela[j].r_offset >= addr + size)
	    continue;
	  if (info->conflict_rela[j].r_offset + dso->arch->max_reloc_size
	      <= addr)
	    continue;

	  reloc_type = GELF_R_TYPE (info->conflict_rela[j].r_info);
	  reloc_size = dso->arch->reloc_size (reloc_type);
	  if (info->conflict_rela[j].r_offset + reloc_size <= addr)
	    continue;

	  off = info->conflict_rela[j].r_offset - addr;

	  /* Check if whole relocation fits into the area.
	     Punt if not.  */
	  if (off < 0 || size - off < reloc_size)
	    return 2;
	  dso->arch->apply_conflict_rela (info, info->conflict_rela + j,
					  buf + off);
	}
    }
  else
    {
      int i, ndx, maxndx;
      int reloc_type, reloc_size;
      union { GElf_Rel rel; GElf_Rela rela; } u;
      off_t off;

      if (addr + size > info->dynbss_base
	  && addr < info->dynbss_base + info->dynbss_size)
	{
	  if (addr < info->dynbss_base
	      || addr + size > info->dynbss_base + info->dynbss_size)
	    return 4;

	  memcpy (buf, info->dynbss + (addr - info->dynbss_base), size);
	  return 0;
	}

      for (i = 1; i < dso->ehdr.e_shnum; ++i)
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
	    case SHT_RELA:
	      break;
	    default:
	      continue;
	    }
	  scn = elf_getscn (dso->elf, i);
	  data = NULL;
	  while ((data = elf_getdata (scn, data)) != NULL)
	    {
	      maxndx = data->d_size / dso->shdr[i].sh_entsize;
	      for (ndx = 0; ndx < maxndx; ++ndx)
		{
		  if (dso->shdr[i].sh_type == SHT_REL)
		    gelfx_getrel (dso->elf, data, ndx, &u.rel);
		  else
		    gelfx_getrela (dso->elf, data, ndx, &u.rela);

		  if (u.rel.r_offset >= addr + size)
		    continue;
		  if (u.rel.r_offset + dso->arch->max_reloc_size <= addr)
		    continue;

		  reloc_type = GELF_R_TYPE (u.rel.r_info);
		  reloc_size = dso->arch->reloc_size (reloc_type);
		  if (u.rel.r_offset + reloc_size <= addr)
		    continue;

		  if (reloc_type == dso->arch->R_COPY)
		    return 3;

		  off = u.rel.r_offset - addr;

		  /* Check if whole relocation fits into the area.
		     Punt if not.  */
		  if (off < 0 || size - off < reloc_size)
		    return 2;

		  if (dso->shdr[i].sh_type == SHT_REL)
		    dso->arch->apply_rel (info, &u.rel, buf + off);
		  else
		    dso->arch->apply_rela (info, &u.rela, buf + off);
		}
	    }
	}
    }

  return 0;
}

static int
prelink_build_conflicts (struct prelink_info *info)
{
  int i, ndeps = info->ent->ndepends + 1;
  struct prelink_entry *ent;
  int ret = 0;
  DSO *dso;
  struct copy_relocs cr;

  info->dsos = alloca (sizeof (struct DSO *) * ndeps);
  memset (info->dsos, 0, sizeof (struct DSO *) * ndeps);
  memset (&cr, 0, sizeof (cr));
  info->dsos[0] = info->dso;
  for (i = 1; i < ndeps; ++i)
    {
      ent = info->ent->depends[i - 1];
      if ((dso = open_dso (ent->filename)) == NULL)
	goto error_out;
      info->dsos[i] = dso;
      /* Now check that the DSO matches what we recorded about it.  */
      if (ent->timestamp != dso->info_DT_GNU_PRELINKED
	  || ent->checksum != dso->info_DT_CHECKSUM
	  || ent->base != dso->base)
	{
	  error (0, 0, "%s: Library %s has changed since it has been prelinked",
		 info->dso->filename, ent->filename);
	  goto error_out;
	}
    }

  for (i = 1; i < ndeps; ++i)
    {
      if (info->conflicts[i])
	{
	  
	  int j, sec, first_conflict;
	  struct prelink_conflict *conflict;

	  dso = info->dsos[i];
	  info->curconflicts = info->conflicts[i];
	  first_conflict = info->conflict_rela_size;
	  sec = addr_to_sec (dso, dso->info[DT_SYMTAB]);
	  /* DT_SYMTAB should be found and should point to
	     start of .dynsym section.  */
	  if (sec == -1
	      || dso->info[DT_SYMTAB] != dso->shdr[sec].sh_addr)
	    {
	      error (0, 0, "Bad symtab");
	      goto error_out;
	    }
	  info->symtab_start = dso->shdr[sec].sh_addr - dso->base;
	  info->symtab_end = info->symtab_start + dso->shdr[sec].sh_size;
	  for (j = 0; j < dso->ehdr.e_shnum; ++j)
	    {
	      if (! (dso->shdr[j].sh_flags & SHF_ALLOC))
		continue;
	      switch (dso->shdr[j].sh_type)
		{
		case SHT_REL:
		  if (prelink_conflict_rel (dso, j, info))
		    goto error_out;
		  break;
		case SHT_RELA:
		  if (prelink_conflict_rela (dso, j, info))
		    goto error_out;
		  break;
		}
	    }

	  for (conflict = info->curconflicts; conflict;
	       conflict = conflict->next)
	    if (! conflict->used)
	      {
		error (0, 0, "%s: Conflict %08llx not found in any relocation",
		       dso->filename, (unsigned long long) conflict->symoff);
		ret = 1;
	      }

	  if (dynamic_info_is_set (dso, DT_TEXTREL)
	      && info->conflict_rela_size > first_conflict)
	    {
	      /* We allow prelinking against non-PIC libraries, as long as
		 no conflict is against read-only segment.  */
	      int k;

	      for (j = first_conflict; j < info->conflict_rela_size; ++j)
		for (k = 0; k < dso->ehdr.e_phnum; ++k)
		  if (dso->phdr[k].p_type == PT_LOAD
		      && (dso->phdr[k].p_flags & PF_W) == 0
		      && dso->phdr[k].p_vaddr
			 <= info->conflict_rela[j].r_offset
		      && dso->phdr[k].p_vaddr + dso->phdr[k].p_memsz
			 > info->conflict_rela[j].r_offset)
		    {
		      error (0, 0, "%s: Cannot prelink against non-PIC shared library %s",
			     info->dso->filename, dso->filename);
		      goto error_out;
		    }
	    }
	}
    }

  dso = info->dso;
  for (i = 0; i < dso->ehdr.e_shnum; ++i)
    {
      if (! (dso->shdr[i].sh_flags & SHF_ALLOC))
	continue;
      switch (dso->shdr[i].sh_type)
	{
	case SHT_REL:
	  if (prelink_find_copy_rel (dso, i, &cr))
	    goto error_out;
	  break;
	case SHT_RELA:
	  if (prelink_find_copy_rela (dso, i, &cr))
	    goto error_out;
	  break;
	}
    }

  if (cr.count)
    {
      int bss;

      qsort (cr.rela, cr.count, sizeof (GElf_Rela), rela_cmp);
      if ((bss = addr_to_sec (dso, cr.rela[0].r_offset))
	  != addr_to_sec (dso, cr.rela[cr.count - 1].r_offset))
	{
	  /* FIXME. When porting to architectures which use both
	     .sbss and emit copy relocs, we need to support that somehow.  */
	  error (0, 0, "%s: Not all copy relocs belong to the same section",
		 dso->filename);
	  goto error_out;
	}
      info->dynbss_size = cr.rela[cr.count - 1].r_offset - cr.rela[0].r_offset;
      info->dynbss_size += cr.rela[cr.count - 1].r_addend;
      info->dynbss = calloc (info->dynbss_size, 1);
      info->dynbss_base = cr.rela[0].r_offset;
      if (info->dynbss == NULL)
	{
	  error (0, ENOMEM, "%s: Cannot build .dynbss", dso->filename);
	  goto error_out;
	}
      /* emacs apparently has .rel.bss relocations against .data section,
	 crap.  */
      if (dso->shdr[bss].sh_type != SHT_NOBITS
	  && strcmp (strptr (dso, dso->ehdr.e_shstrndx,
			     dso->shdr[bss].sh_name),
		     ".dynbss") != 0)
	{
	  error (0, 0, "%s: COPY relocations don't point into .bss section",
		 dso->filename);
	  goto error_out;
	}
      for (i = 0; i < cr.count; ++i)
	{
	  struct prelink_symbol *s;
	  DSO *ndso = NULL;
	  int j, reloc_class;

	  reloc_class
	    = dso->arch->reloc_class (GELF_R_TYPE (cr.rela[i].r_info));

	  for (s = & info->symbols[GELF_R_SYM (cr.rela[i].r_info)]; s;
	       s = s->next)
	    if (s->reloc_class == reloc_class)
	      break;

	  if (s == NULL || s->ent == NULL)
	    {
	      error (0, 0, "%s: Could not find symbol copy reloc is against",
		     dso->filename);
	      goto error_out;
	    }

	  for (j = 1; j < ndeps; ++j)
	    if (info->ent->depends[j - 1] == s->ent)
	      {
		ndso = info->dsos[j];
		break;
	      }

	  assert (j < ndeps);
	  j = get_relocated_mem (info, ndso, s->ent->base + s->value,
				 info->dynbss + cr.rela[i].r_offset
				 - info->dynbss_base, cr.rela[i].r_addend);
	  switch (j)
	    {
	    case 1:
	      error (0, 0, "%s: Could not find variable copy reloc is against",
		     dso->filename);
	      goto error_out;
	    case 2:
	      error (0, 0, "%s: Conflict partly overlaps with %08llx-%08llx area",
		     dso->filename,
		     (long long) cr.rela[i].r_offset,
		     (long long) cr.rela[i].r_offset + cr.rela[i].r_addend);
	      goto error_out;
	    }
	}
    }

  if (info->conflict_rela_size)
    {
      qsort (info->conflict_rela, info->conflict_rela_size, sizeof (GElf_Rela),
	     rela_cmp);
      if (enable_cxx_optimizations && remove_redundant_cxx_conflicts (info))
	goto error_out;
    }

  for (i = 1; i < ndeps; ++i)
    if (info->dsos[i])
      close_dso (info->dsos[i]);

  info->dsos = NULL;
  free (cr.rela);
  return ret;

error_out:
  free (cr.rela);
  free (info->dynbss);
  info->dynbss = NULL;
  for (i = 1; i < ndeps; ++i)
    if (info->dsos[i])
      close_dso (info->dsos[i]);
  return 1;
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
  int old[5], new[5];
  int addcnt, undo = 0;
  struct reloc_info rinfo;
  DSO *dso = info->dso;
  GElf_Ehdr ehdr;
  Elf_Data rel_dyn_data;
  GElf_Phdr phdr[dso->ehdr.e_phnum + 1];
  GElf_Shdr old_shdr[dso->ehdr.e_shnum], new_shdr[dso->ehdr.e_shnum + 20];
  GElf_Shdr *shdr, add[5];
  Elf32_Lib *liblist = NULL;
  struct readonly_adjust adjust;
  struct section_move *move = NULL;

  memset (&rel_dyn_data.d_buf, 0, sizeof (rel_dyn_data));

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
  for (i = 1, j = 1; i < dso->ehdr.e_shnum; ++i)
    {
      const char *name = strptr (dso, dso->ehdr.e_shstrndx,
				 dso->shdr[i].sh_name);
      if (! strcmp (name, ".dynbss"))
	old_dynbss = i;
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
      else if (i > rinfo.first && i <= rinfo.last)
	{
	  shdr[j - 1].sh_size = dso->shdr[i].sh_addr
				 + dso->shdr[i].sh_size
				 - shdr[j - 1].sh_addr;
	  remove_section (move, move->old_to_new[i]);
	}
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

  memset (add, 0, sizeof (add));
  memset (old, 0, sizeof (old));
  memset (new, 0, sizeof (new));

  if (rinfo.first && ! rinfo.reldyn)
    {
      if (build_rel_dyn (dso, &rel_dyn_data, &rinfo))
	goto error_out;
    }

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
      if (rinfo.plt)
	{
	  add[i] = dso->shdr[rinfo.plt];
	  if (rinfo.rel_to_rela_plt)
	    add[i].sh_size = add[i].sh_size / 2 * 3;
	  /* Temporarily merge them, so that they are allocated adjacently.  */
	  add[i - 1].sh_size += add[i].sh_size;
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

  for (i = 0; i < addcnt; ++i)
    {
      int k = 1;

      new[i] = find_readonly_space (dso, add + i, &ehdr, phdr, shdr, &adjust);
      if (new[i] == 0)
	goto error_out;
      add_section (move, new[i]);
      if (i == new_reloc && new_plt != -1)
	k = 2;
      for (j = 0; j < i; ++j)
	if (new[j] >= new[i])
	  new[j] += k;
      if (old[i])
	{
	  move->old_to_new[old[i]] = new[i];
	  move->new_to_old[new[i]] = old[i];
	}
      if (k == 2)
	{
	  k = new[i];
	  shdr[k].sh_size -= add[i+1].sh_size;
	  memmove (&shdr[k + 2], &shdr[k + 1],
		   (ehdr.e_shnum - k - 1) * sizeof (GElf_Shdr));
	  ++ehdr.e_shnum;
	  shdr[k + 1] = add[i + 1];
	  shdr[k + 1].sh_addr = shdr[k].sh_addr + shdr[k].sh_size;
	  shdr[k + 1].sh_offset = shdr[k].sh_offset + shdr[k].sh_size;
	  new[i + 1] = k + 1;
	  add_section (move, k + 1);
	  move->old_to_new[rinfo.plt] = k + 1;
	  move->new_to_old[k + 1] = rinfo.plt;
	  ++i;
	}
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
	    Elf_Data *data = elf_getdata (elf_getscn (dso->elf, i), NULL);

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

	for (j = 1; j < dso->ehdr.e_shnum; ++j)
	  if (dso->shdr[j].sh_addr >= dso->phdr[i].p_vaddr
	      && dso->shdr[j].sh_addr + dso->shdr[j].sh_size
		 <= dso->phdr[i].p_vaddr + dso->phdr[i].p_memsz)
	    {
	      if (dso->shdr[j].sh_type == SHT_NOBITS)
		{
		  last_offset += dso->shdr[j].sh_addralign - 1;
		  last_offset &= ~(dso->shdr[j].sh_addralign - 1);
		  if (last_offset > dso->phdr[i].p_offset
				    + dso->phdr[i].p_filesz)
		    last_offset = dso->phdr[i].p_offset
				  + dso->phdr[i].p_filesz;
		  dso->shdr[j].sh_offset = last_offset;
		  shdr[j].sh_offset = last_offset;
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
		  shdr[j].sh_offset = dso->shdr[j].sh_offset;
		  last_offset = dso->shdr[j].sh_offset + dso->shdr[j].sh_size;
		}
	    }
      }

  /* Create .rel*.dyn if necessary.  */
  rinfo.first = move->old_to_new[rinfo.first];
  assert (new_reloc == -1 || rinfo.first == new[new_reloc]);

  if (rinfo.first && ! rinfo.reldyn)
    {
      Elf_Data *data;

      i = rinfo.first;
      data = elf_getdata (elf_getscn (dso->elf, i), NULL);
      free (data->d_buf);
      memcpy (data, &rel_dyn_data, sizeof (rel_dyn_data));
      rel_dyn_data.d_buf = NULL;
      dso->shdr[i].sh_info = 0;
      dso->shdr[i].sh_name = shstrtabadd (dso, data->d_type == ELF_T_REL
					       ? ".rel.dyn" : ".rela.dyn");
      if (dso->shdr[i].sh_name == 0)
	goto error_out;
    }

  if (rinfo.rel_to_rela)
    {
      assert (sizeof (Elf32_Rel) * 3 == sizeof (Elf32_Rela) * 2);
      assert (sizeof (Elf64_Rel) * 3 == sizeof (Elf64_Rela) * 2);
      dso->shdr[rinfo.first].sh_size
	= dso->shdr[rinfo.first].sh_size / 3 * 2;
      if (convert_rel_to_rela (dso, rinfo.first))
	goto error_out;
      dso->shdr[rinfo.first].sh_size = shdr[rinfo.first].sh_size;
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
      data = elf_getdata (elf_getscn (dso->elf, i), NULL);
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
	      for (i = 0; i < dso->ehdr.e_phnum; ++i)
		if (dso->phdr[i].p_type == PT_LOAD
		    && dso->phdr[i].p_vaddr <= dso->shdr[new_dynbss].sh_addr
		    && dso->phdr[i].p_vaddr + dso->phdr[i].p_memsz
		       >= info->dynbss_base + info->dynbss_size)
		  break;
	      assert (i < dso->ehdr.e_phnum);

	      if (dso->shdr[new_dynbss].sh_offset
		  != dso->phdr[i].p_offset + dso->shdr[new_dynbss].sh_addr
		     - dso->phdr[i].p_vaddr)
		{
		  error (0, 0, "%s: COPY relocs not present at start of first SHT_NOBITS section",
			 dso->filename);
		  goto error_out;
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

	      adj = dso->shdr[new_dynbss].sh_size;
	      for (j = new_dynbss + 2;
		   j < dso->ehdr.e_shnum
		   && (dso->shdr[j].sh_flags
		       & (SHF_WRITE | SHF_ALLOC | SHF_EXECINSTR));
		   ++j)
		adj = (adj + dso->shdr[new_dynbss].sh_addralign - 1)
		      & ~(dso->shdr[new_dynbss].sh_addralign - 1);

	      for (++i; i < dso->ehdr.e_phnum; ++i)
		if (dso->phdr[i].p_type == PT_LOAD
		    && dso->phdr[i].p_vaddr >= dso->shdr[new_dynbss].sh_addr)
		  {
		    dso->phdr[i].p_vaddr += adj;
		    dso->phdr[i].p_paddr += adj;
		    dso->phdr[i].p_offset += adj;
		  }

	      for (j = new_dynbss + 2;
		   j < dso->ehdr.e_shnum
		   && (dso->shdr[j].sh_flags
		       & (SHF_WRITE | SHF_ALLOC | SHF_EXECINSTR));
		   ++j)
		{
		  dso->shdr[j].sh_offset += adj;
		  dso->shdr[j].sh_addr += adj;
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
      data = elf_getdata (elf_getscn (dso->elf, new_dynbss), NULL);
      free (data->d_buf);
      data->d_buf = info->dynbss;
      info->dynbss = NULL;
      data->d_off = info->dynbss_base - dso->shdr[new_dynbss].sh_addr;
      data->d_size = info->dynbss_size;
      data->d_type = ELF_T_BYTE;
      if (old_dynbss == -1)
	{
	  data = elf_getdata (elf_getscn (dso->elf, new_dynbss + 1), NULL);
	  assert (dso->shdr[new_dynbss + 1].sh_type != SHT_NOBITS
		  || data->d_buf == NULL);
	  assert (data->d_size == dso->shdr[new_dynbss].sh_size
				  + dso->shdr[new_dynbss + 1].sh_size);
	  data->d_size -= dso->shdr[new_dynbss].sh_size;
	}
    }

  /* Create the liblist.  */
  i = new[new_liblist];
  dso->shdr[i] = shdr[i];
  dso->shdr[i].sh_name = shstrtabadd (dso, ".gnu.liblist");
  if (dso->shdr[i].sh_name == 0)
    goto error_out;
  else
    {
      Elf_Data *data;

      dso->shdr[i].sh_link
	= new_dynstr ? new[new_dynstr] : move->old_to_new[dynstrndx];
      data = elf_getdata (elf_getscn (dso->elf, i), NULL);
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
      data = elf_getdata (elf_getscn (dso->elf, i), NULL);
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

      dso->shdr[i] = shdr[i];
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
      dso->shdr[undo].sh_entsize = gelf_fsize (dso->elf, ELF_T_SHDR, 1,
					       EV_CURRENT);
      dso->shdr[undo].sh_size = dso->undo.d_size;
      newoffset = dso->shdr[undo].sh_offset + dso->undo.d_align - 1;
      newoffset &= ~(dso->shdr[undo].sh_addralign - 1);
      if (adjust_dso_nonalloc (dso, undo + 1, dso->shdr[undo].sh_offset,
			       dso->undo.d_size + newoffset
			       - dso->shdr[undo].sh_offset))
	return 1;
      dso->shdr[undo].sh_offset = newoffset;
      scn = elf_getscn (dso->elf, undo);
      data = elf_getdata (scn, NULL);
      assert (data != NULL && elf_getdata (scn, data) == NULL);
      free (data->d_buf);
      *data = dso->undo;
      dso->undo.d_buf = NULL;
    }

  if (update_dynamic_tags (dso, old_shdr, move))
    goto error_out;

  if (update_dynamic_rel (dso, &rinfo))
    goto error_out;

  free (move);
  return 0;

error_out:
  free (rel_dyn_data.d_buf);
  free (liblist);
  free (move);
  return 1;
}
