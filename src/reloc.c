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

int
find_reloc_sections (DSO *dso, struct reloc_info *rinfo)
{
  int first, last, rela, i;
  GElf_Addr start, end, pltstart, pltend;

  memset (rinfo, 0, sizeof (*rinfo));

  if (dso->info[DT_REL] && dso->info[DT_RELA])
    {
      error (0, 0, "%s: Cannot prelink object with both DT_REL and DT_RELA tags",
	     dso->filename);
      return 1;
    }

  rela = dso->info[DT_RELA] != 0;

  if (rela)
    {
      start = dso->info[DT_RELA];
      end = dso->info[DT_RELA] + dso->info[DT_RELASZ];
    }
  else
    {
      start = dso->info[DT_REL];
      end = dso->info[DT_REL] + dso->info[DT_RELSZ];
    }

  if (dso->info[DT_JMPREL])
    {
      pltstart = dso->info[DT_JMPREL];
      pltend = dso->info[DT_JMPREL] + dso->info[DT_PLTRELSZ];
      first = addr_to_sec (dso, pltstart);
      last = addr_to_sec (dso, pltend - 1);
      if (first == -1
	  || last == -1
	  || first != last
	  || dso->shdr[first].sh_addr != pltstart
	  || dso->shdr[first].sh_addr + dso->shdr[first].sh_size != pltend
	  || (dso->info[DT_PLTREL] != DT_REL
	      && dso->info[DT_PLTREL] != DT_RELA)
	  || dso->shdr[first].sh_type
	     != (dso->info[DT_PLTREL] == DT_RELA ? SHT_RELA : SHT_REL)
	  || strcmp (strptr (dso, dso->ehdr.e_shstrndx,
			     dso->shdr[first].sh_name),
		     dso->info[DT_PLTREL] == DT_RELA
		     ? ".rela.plt" : ".rel.plt"))
	{
	  error (0, 0, "%s: DT_JMPREL tags don't surround .rel%s.plt section",
		 dso->filename, dso->info[DT_PLTREL] == DT_RELA ? "a" : "");
	  return 1;
	}
      rinfo->plt = first;
      if (dso->shdr[first].sh_type == SHT_REL
	  && dso->arch->need_rel_to_rela (dso, first, first))
	rinfo->rel_to_rela_plt = 1;
    }
  else
    {
      pltstart = end;
      pltend = end;
    }

  if (! rela && dso->info[DT_REL] == 0)
    {
      /* No non-PLT relocations.  */
      return 0;
    }

  first = addr_to_sec (dso, start);
  last = addr_to_sec (dso, end - 1);

  if (first == -1
      || last == -1
      || dso->shdr[first].sh_addr != start
      || dso->shdr[last].sh_addr + dso->shdr[last].sh_size != end)
    {
      error (0, 0, "%s: DT_REL%s tags don't surround whole relocation sections",
	     dso->filename, rela ? "A" : "");
      return 1;
    }

  for (i = first; i <= last; i++)
    if (dso->shdr[i].sh_type != (rela ? SHT_RELA : SHT_REL))
      {
	error (0, 0, "%s: DT_REL%s tags don't surround relocation sections of expected type",
	       dso->filename, rela ? "A" : "");
	return 1;
      }

  if (pltstart != end && pltend != end)
    {
      error (0, 0, "%s: DT_JMPREL tag not adjacent to DT_REL%s relocations",
	     dso->filename, rela ? "A" : "");
      return 1;
    }

  if (pltstart == start && pltend == end)
    {
      /* No non-PLT relocations.  */
      rinfo->overlap = 1;
      return 0;
    }

  if (pltend == end)
    {
      rinfo->overlap = 1;
      --last;
    }

  if (! strcmp (strptr (dso, dso->ehdr.e_shstrndx,
			dso->shdr[first].sh_name),
		".gnu.reloc"))
    rinfo->gnureloc = 1;
  rinfo->first = first;
  rinfo->last = last;
  if (! rela && dso->arch->need_rel_to_rela (dso, first, last))
    rinfo->rel_to_rela = 1;
  return 0;
}

static struct PLArch *arch;

struct sort_gnu_reloc {
  GElf_Rela rela;
  GElf_Addr offset;
};

static int
gnu_reloc_cmp1 (const void *A, const void *B)
{
  struct sort_gnu_reloc *a = (struct sort_gnu_reloc *)A;
  struct sort_gnu_reloc *b = (struct sort_gnu_reloc *)B;
  int relativea, relativeb;

  relativea = GELF_R_TYPE (a->rela.r_info) == arch->R_RELATIVE;
  relativeb = GELF_R_TYPE (b->rela.r_info) == arch->R_RELATIVE;

  if (relativea < relativeb)
    return -1;
  if (relativea > relativeb)
    return 1;
  if (GELF_R_SYM (a->rela.r_info) < GELF_R_SYM (b->rela.r_info))
    return -1;
  if (GELF_R_SYM (a->rela.r_info) > GELF_R_SYM (b->rela.r_info))
    return 1;
  if (a->rela.r_offset < b->rela.r_offset)
    return -1;
  if (a->rela.r_offset > b->rela.r_offset)
    return 1;
  return 0;
}

static int
gnu_reloc_cmp2 (const void *A, const void *B)
{
  struct sort_gnu_reloc *a = (struct sort_gnu_reloc *)A;
  struct sort_gnu_reloc *b = (struct sort_gnu_reloc *)B;
  int plta, pltb;

  if (a->offset < b->offset)
    return -1;
  if (a->offset > b->offset)
    return 1;
  plta = (GELF_R_TYPE (a->rela.r_info) == arch->R_COPY) * 2
	 + (GELF_R_TYPE (a->rela.r_info) == arch->R_JMP_SLOT);
  pltb = (GELF_R_TYPE (b->rela.r_info) == arch->R_COPY) * 2
	 + (GELF_R_TYPE (b->rela.r_info) == arch->R_JMP_SLOT);
  if (plta < pltb)
    return -1;
  if (plta > pltb)
    return 1;
  if (a->rela.r_offset < b->rela.r_offset)
    return -1;
  if (a->rela.r_offset > b->rela.r_offset)
    return 1;
  return 0;
}

int
build_gnu_reloc (DSO *dso, Elf_Data *data, struct reloc_info *rinfo)
{
  int first = rinfo->first, last = rinfo->last;
  int i, j, count, rela;
  Elf_Data *d, *dlast = NULL;
  Elf_Scn *scn;
  off_t offset;
  size_t size;
  char *ptr;
  struct sort_gnu_reloc *array, *a;

  size = dso->shdr[last].sh_addr + dso->shdr[last].sh_size
	 - dso->shdr[first].sh_addr;
  count = size / dso->shdr[first].sh_entsize;
  array = alloca (count * sizeof (struct sort_gnu_reloc));
  memset (array, 0, count * sizeof (struct sort_gnu_reloc));
  ptr = calloc (1, size);
  rela = dso->shdr[first].sh_type == SHT_RELA;
  if (ptr == NULL)
    {
      error (0, ENOMEM, "%s: Cannot build .gnu.reloc section",
	     dso->filename);
      return 1;
    }

  for (i = first, a = array; i <= last; i++)
    {
      d = NULL;
      scn = elf_getscn (dso->elf, i);
      offset = dso->shdr[i].sh_addr - dso->shdr[first].sh_addr;
      while ((d = elf_getdata (scn, d)) != NULL)
	{
	  int ndx, maxndx;

	  dlast = d;
	  maxndx = d->d_size / dso->shdr[i].sh_entsize;
	  if (rela)
	    {
	      for (ndx = 0; ndx < maxndx; ++ndx, ++a)
		gelfx_getrela (dso->elf, d, ndx, &a->rela);
	    }
	  else
	    {
	      for (ndx = 0; ndx < maxndx; ++ndx, ++a)
		gelfx_getrel (dso->elf, d, ndx, (GElf_Rel *)&a->rela);
            }
	}
    }

  arch = dso->arch;
  /* First sort so that R_*_RELATIVE records come last, then so that
     relocs with the same symbol are together and within the same symbol
     according to r_offset.  */
  qsort (array, count, sizeof (struct sort_gnu_reloc), gnu_reloc_cmp1);
  for (i = 0, j = 0;
       i < count && GELF_R_TYPE (array[i].rela.r_info) != arch->R_RELATIVE;
       i++)
    {
      if (GELF_R_SYM (array[i].rela.r_info)
	  != GELF_R_SYM (array[j].rela.r_info))
	j = i;
      array[i].offset = array[j].rela.r_offset;
    }

  /* Number of R_*_RELATIVE relocs.  */
  rinfo->relcount = count - i;

  /* Now second sort, which will sort things by increasing r_offset, with
     the exception that relocs against the same symbol will be together.  */
  qsort (array, i, sizeof (struct sort_gnu_reloc), gnu_reloc_cmp2);
  data->d_buf = ptr;
  data->d_off = 0;
  data->d_size = size;
  data->d_version = dlast->d_version;
  data->d_align = dlast->d_align;
  data->d_type = dlast->d_type;
  for (i = 0, a = array; i < count; i++, a++)
    if (rela)
      gelfx_update_rela (dso->elf, data, i, &a->rela);
    else
      gelfx_update_rel (dso->elf, data, i, (GElf_Rel *)&a->rela);
  return 0;
}

int
convert_rel_to_rela (DSO *dso, int i)
{
  Elf_Data d1, d2, *d;
  Elf_Scn *scn;
  GElf_Rel rel;
  GElf_Rela rela;
  int ndx, maxndx;

  scn = elf_getscn (dso->elf, i);
  d = elf_getdata (scn, NULL);
  assert (elf_getdata (scn, d) == NULL);
  assert (d->d_off == 0);
  assert (d->d_size == dso->shdr[i].sh_size);
  d1 = *d;
  d2 = *d;
  assert (sizeof (Elf32_Rel) * 3 == sizeof (Elf32_Rela) * 2);
  assert (sizeof (Elf64_Rel) * 3 == sizeof (Elf64_Rela) * 2);
  d1.d_size = d->d_size / 2 * 3;
  d1.d_buf = malloc (d1.d_size);
  d1.d_type = ELF_T_RELA;
  if (d1.d_buf == NULL)
    {
      error (0, ENOMEM, "Cannot convert REL section to RELA");
      return 1;
    }

  maxndx = d->d_size / dso->shdr[i].sh_entsize;
  for (ndx = 0; ndx < maxndx; ndx++)
    {
      if (gelfx_getrel (dso->elf, d, ndx, &rel) == 0
	  || dso->arch->rel_to_rela (dso, &rel, &rela))
        {
	  free (d1.d_buf);
	  return 1;
        }
      /* gelf_update_rel etc. should have Elf * argument, so that
	 we don't have to do this crap.  */
      *d = d1;
      if (gelfx_update_rela (dso->elf, d, ndx, &rela) == 0)
        {
	  *d = d2;
	  free (d1.d_buf);
	  return 1;
        }
      *d = d2;
    }

  free (d2.d_buf);
  *d = d1;
  dso->shdr[i].sh_entsize
    = gelf_fsize (dso->elf, ELF_T_RELA, 1, EV_CURRENT);
  dso->shdr[i].sh_type = SHT_RELA;
  return 0;
}

int
update_dynamic_rel (DSO *dso, struct reloc_info *rinfo)
{
  GElf_Dyn *info[DT_NUM], *dynamic = NULL;
  int rel = rinfo->first, plt = rinfo->plt, overlap = rinfo->overlap;
  int dynsec, count = 0, loc;
  Elf_Data *data;
  Elf_Scn *scn = NULL;

  memset (&info, 0, sizeof (info));
  for (dynsec = 0; dynsec < dso->ehdr.e_shnum; dynsec++)
    if (dso->shdr[dynsec].sh_type == SHT_DYNAMIC)
      {
	scn = elf_getscn (dso->elf, dynsec);
	dynamic = alloca (dso->shdr[dynsec].sh_size
			  / dso->shdr[dynsec].sh_entsize * sizeof (GElf_Dyn));
	loc = 0;
	data = NULL;
	while ((data = elf_getdata (scn, data)) != NULL)
	  {
	    int ndx, maxndx;

	    maxndx = data->d_size / dso->shdr[dynsec].sh_entsize;
	    for (ndx = 0; ndx < maxndx; ++ndx, ++loc)
	      {
		gelfx_getdyn (dso->elf, data, ndx, dynamic + loc);
		if (dynamic[loc].d_tag == DT_NULL)
		  break;
		else if (dynamic[loc].d_tag < DT_NUM)
		  info[dynamic[loc].d_tag] = dynamic + loc;
	      }
	    if (ndx < maxndx)
	      break;
	  }
	count = loc;
	break;
      }

  if (rel && plt && overlap)
    {
      if (dso->shdr[rel].sh_type != dso->shdr[plt].sh_type)
	overlap = 0;
    }

  if (rel || (plt && overlap))
    {
      assert (dso->info[DT_RELENT]
	      == gelf_fsize (dso->elf, ELF_T_REL, 1, EV_CURRENT));
      assert (dso->info[DT_REL] != 0);
      assert (dso->info[DT_RELSZ] != 0);

      info[DT_REL]->d_un.d_ptr = dso->shdr[rel ?: plt].sh_addr;
      if (plt && overlap)
	info[DT_RELSZ]->d_un.d_val =
	  dso->shdr[plt].sh_addr + dso->shdr[plt].sh_size;
      else
	info[DT_RELSZ]->d_un.d_val =
	  dso->shdr[rel].sh_addr + dso->shdr[rel].sh_size;
      info[DT_RELSZ]->d_un.d_val -= info[DT_REL]->d_un.d_ptr;

      if (dso->shdr[rel ?: plt].sh_type == SHT_RELA)
	{
	  info[DT_RELENT]->d_un.d_val =
	    gelf_fsize (dso->elf, ELF_T_RELA, 1, EV_CURRENT);
	  info[DT_REL]->d_tag = DT_RELA;
	  info[DT_RELSZ]->d_tag = DT_RELASZ;
	  info[DT_RELENT]->d_tag = DT_RELAENT;
	}
    }

  if (plt)
    {
      assert (dso->info[DT_JMPREL] != 0);
      assert (dso->info[DT_PLTREL] == DT_REL);

      info[DT_JMPREL]->d_un.d_ptr = dso->shdr[plt].sh_addr;
      if (dso->shdr[plt].sh_type == SHT_RELA)
	{
	  info[DT_PLTREL]->d_un.d_val = DT_RELA;
	  info[DT_PLTRELSZ]->d_un.d_val = dso->shdr[plt].sh_size;
	}
    }

  loc = 0;
  data = NULL;
  while ((data = elf_getdata (scn, data)) != NULL)
    {
      int ndx, maxndx;

      maxndx = data->d_size / dso->shdr[dynsec].sh_entsize;
      for (ndx = 0; ndx < maxndx && loc < count; ++ndx, ++loc)
	if (dynamic[loc].d_tag < DT_NUM)
	  gelfx_update_dyn (dso->elf, data, ndx, dynamic + loc);
      if (ndx < maxndx)
	break;
    }

  read_dynamic (dso);
  return 0;
}
