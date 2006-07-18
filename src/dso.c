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
#include <string.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>
#include <utime.h>
#include "prelink.h"

#define RELOCATE_SCN(shf) \
  ((shf) & (SHF_WRITE | SHF_ALLOC | SHF_EXECINSTR))

void
read_dynamic (DSO *dso)
{
  int i;

  memset (dso->info, 0, sizeof(dso->info));
  dso->info_set_mask = 0;
  for (i = 0; i < dso->ehdr.e_shnum; i++)
    if (dso->shdr[i].sh_type == SHT_DYNAMIC)
      {
	Elf_Data *data = NULL;
	Elf_Scn *scn = elf_getscn (dso->elf, i);
	GElf_Dyn dyn;

	dso->dynamic = i;
	while ((data = elf_getdata (scn, data)) != NULL)
	  {
	    int ndx, maxndx;

	    maxndx = data->d_size / dso->shdr[i].sh_entsize;
	    for (ndx = 0; ndx < maxndx; ++ndx)
	      {
		gelfx_getdyn (dso->elf, data, ndx, &dyn);
		if (dyn.d_tag == DT_NULL)
		  break;
		else if (dyn.d_tag < DT_NUM)
		  {
		    dso->info[dyn.d_tag] = dyn.d_un.d_val;
		    if (dyn.d_tag < 50)
		      dso->info_set_mask |= (1ULL << dyn.d_tag);
		  }
		else if (dyn.d_tag == DT_CHECKSUM)
		  {
		    dso->info_DT_CHECKSUM = dyn.d_un.d_val;
		    dso->info_set_mask |= (1ULL << DT_CHECKSUM_BIT);
		  }
		else if (dyn.d_tag == DT_GNU_PRELINKED)
		  {
		    dso->info_DT_GNU_PRELINKED = dyn.d_un.d_val;
		    dso->info_set_mask |= (1ULL << DT_GNU_PRELINKED_BIT);
		  }
		else if (dyn.d_tag == DT_VERDEF)
		  {
		    dso->info_DT_VERDEF = dyn.d_un.d_val;
		    dso->info_set_mask |= (1ULL << DT_VERDEF_BIT);
		  }
		else if (dyn.d_tag == DT_VERNEED)
		  {
		    dso->info_DT_VERNEED = dyn.d_un.d_val;
		    dso->info_set_mask |= (1ULL << DT_VERNEED_BIT);
		  }
		else if (dyn.d_tag == DT_VERSYM)
		  {
		    dso->info_DT_VERSYM = dyn.d_un.d_val;
		    dso->info_set_mask |= (1ULL << DT_VERSYM_BIT);
		  }
	      }
	    if (ndx < maxndx)
	      break;
	  }
      }
}

int
set_dynamic (DSO *dso, GElf_Word tag, GElf_Addr value, int fatal)
{
  Elf_Data *data;
  Elf_Scn *scn;
  GElf_Dyn dyn;
  int ndx, maxndx;
  int pt_dynamic, pt_load, i;
  uint64_t mask = dso->info_set_mask;

  assert (dso->shdr[dso->dynamic].sh_type == SHT_DYNAMIC);

  scn = elf_getscn (dso->elf, dso->dynamic);

  data = elf_getdata (scn, NULL);
  assert (elf_getdata (scn, data) == NULL);

  switch (tag)
    {
    case DT_CHECKSUM:
      mask |= (1ULL << DT_CHECKSUM_BIT); break;
    case DT_GNU_PRELINKED:
      mask |= (1ULL << DT_GNU_PRELINKED_BIT); break;
    case DT_VERDEF:
      mask |= (1ULL << DT_VERDEF_BIT); break;
    case DT_VERNEED:
      mask |= (1ULL << DT_VERNEED_BIT); break;
    case DT_VERSYM:
      mask |= (1ULL << DT_VERSYM_BIT); break;
    default:
      if (tag < DT_NUM && tag < 50)
	mask |= (1ULL << tag);
      break;
    }

  maxndx = data->d_size / dso->shdr[dso->dynamic].sh_entsize;
  for (ndx = 0; ndx < maxndx; ndx++)
    {
      gelfx_getdyn (dso->elf, data, ndx, &dyn);
      if (dyn.d_tag == DT_NULL)
        break;
      else if (dyn.d_tag == tag)
	{
	  if (dyn.d_un.d_ptr != value)
	    {
	      dyn.d_un.d_ptr = value;
	      gelfx_update_dyn (dso->elf, data, ndx, &dyn);
	      elf_flagscn (scn, ELF_C_SET, ELF_F_DIRTY);
	    }

	  return 0;
	}
    }
  assert (ndx < maxndx);

  pt_dynamic = -1;
  pt_load = -1;
  for (i = 0; i < dso->ehdr.e_phnum; ++i)
    if (dso->phdr[i].p_type == PT_DYNAMIC)
      pt_dynamic = i;
    else if (dso->phdr[i].p_type == PT_LOAD
	     && dso->phdr[i].p_offset + dso->phdr[i].p_filesz
		== dso->shdr[dso->dynamic].sh_offset
		   + dso->shdr[dso->dynamic].sh_size)
      pt_load = i;

  assert (pt_dynamic != -1);
  assert (dso->phdr[pt_dynamic].p_vaddr == dso->shdr[dso->dynamic].sh_addr);
  assert (dso->phdr[pt_dynamic].p_offset
	  == dso->shdr[dso->dynamic].sh_offset);
  assert (dso->phdr[pt_dynamic].p_filesz == dso->shdr[dso->dynamic].sh_size);

  if (ndx + 1 < maxndx)
    {
      /* The easy case: DT_NULL is not the last dynamic
	 entry.  */
      gelfx_update_dyn (dso->elf, data, ndx + 1, &dyn);
      dyn.d_tag = tag;
      dyn.d_un.d_ptr = value;
      gelfx_update_dyn (dso->elf, data, ndx, &dyn);
      dso->info_set_mask = mask;
      elf_flagscn (scn, ELF_C_SET, ELF_F_DIRTY);
      return 0;
    }

  if (! RELOCATE_SCN (dso->shdr[dso->dynamic + 1].sh_flags))
    {
      /* FIXME: Handle this. May happen e.g. if there is no .bss.  */
      if (fatal)
	error (0, 0, "%s: Not enough room to add .dynamic entry",
	       dso->filename);
      return 1;
    }
  else if (dso->shdr[dso->dynamic].sh_addr
	   + dso->shdr[dso->dynamic].sh_size
	   + dso->shdr[dso->dynamic].sh_entsize
	   > dso->shdr[dso->dynamic + 1].sh_addr)
    {
      /* FIXME: Can still try, if after .dynamic is empty .sbss,
	 we could move it, provided that there is some gap before .bss.  */
      if (fatal)
	error (0, 0, "%s: Not enough room to add .dynamic entry",
	       dso->filename);
      return 1;
    }

  dso->shdr[dso->dynamic].sh_size += dso->shdr[dso->dynamic].sh_entsize;
  data->d_buf = realloc (data->d_buf, dso->shdr[dso->dynamic].sh_size);
  if (data->d_buf == NULL)
    {
      if (fatal)
	error (0, ENOMEM, "%s: Could not add .dynamic entry", dso->filename);
      return 1;
    }
  data->d_size = dso->shdr[dso->dynamic].sh_size;
  /* Put in DT_NULL.  */
  gelfx_update_dyn (dso->elf, data, ndx + 1, &dyn);
  dyn.d_tag = tag;
  dyn.d_un.d_ptr = value;
  gelfx_update_dyn (dso->elf, data, ndx, &dyn);
  elf_flagscn (scn, ELF_C_SET, ELF_F_DIRTY);
  for (i = 1; i < dso->ehdr.e_shnum; i++)
    if (dso->shdr[i].sh_offset
	== dso->phdr[pt_dynamic].p_offset + dso->phdr[pt_dynamic].p_filesz)
      {
	if (adjust_dso_nonalloc (dso, 0,
				 dso->phdr[pt_dynamic].p_offset
				 + dso->phdr[pt_dynamic].p_filesz,
				 dso->shdr[dso->dynamic].sh_entsize))
	  return 1;
	break;
      }
  dso->phdr[pt_dynamic].p_filesz += dso->shdr[dso->dynamic].sh_entsize;
  dso->phdr[pt_dynamic].p_memsz += dso->shdr[dso->dynamic].sh_entsize;
  gelf_update_phdr (dso->elf, pt_dynamic, dso->phdr + pt_dynamic);
  if (pt_load != -1)
    {
      if (dso->phdr[pt_load].p_memsz == dso->phdr[pt_load].p_filesz)
	dso->phdr[pt_load].p_memsz += dso->shdr[dso->dynamic].sh_entsize;
      dso->phdr[pt_load].p_filesz += dso->shdr[dso->dynamic].sh_entsize;
      gelf_update_phdr (dso->elf, pt_load, dso->phdr + pt_load);
    }
  dso->info_set_mask = mask;
  elf_flagphdr (dso->elf, ELF_C_SET, ELF_F_DIRTY);
  return 0;
}

int
check_dso (DSO *dso)
{
  int i;

  /* FIXME: Several routines in prelink and in libelf-0.7.0 too
     rely on sh_offset's monotonically increasing.  */
  for (i = 2; i < dso->ehdr.e_shnum; ++i)
    if (dso->shdr[i - 1].sh_offset
	+ (dso->shdr[i - 1].sh_type == SHT_NOBITS
	   ? 0 : dso->shdr[i - 1].sh_size) > dso->shdr[i].sh_offset)
      {
	error (0, 0, "%s: section file offsets not monotonically increasing",
	       dso->filename);
	return 1;
      }
  return 0;
}

DSO *
open_dso (const char *name)
{
  int fd;

  fd = open (name, O_RDONLY);
  if (fd == -1)
    {
      error (0, errno, "cannot open \"%s\"", name);
      return NULL;
    }
  return fdopen_dso (fd, name);
}

DSO *
fdopen_dso (int fd, const char *name)
{
  Elf *elf = NULL;
  GElf_Ehdr ehdr;
  int i;
  DSO *dso = NULL;
  struct PLArch *plarch;
  extern struct PLArch __start_pl_arch[], __stop_pl_arch[];

  elf = elf_begin (fd, ELF_C_READ, NULL);
  if (elf == NULL)
    {
      error (0, 0, "cannot open ELF file: %s", elf_errmsg (-1));
      goto error_out;
    }

  if (elf_kind (elf) != ELF_K_ELF)
    {
      error (0, 0, "\"%s\" is not an ELF file", name);
      goto error_out;
    }

  if (gelf_getehdr (elf, &ehdr) == NULL)
    {
      error (0, 0, "cannot get the ELF header: %s",
	     elf_errmsg (-1));
      goto error_out;
    }

  if (ehdr.e_type != ET_DYN && ehdr.e_type != ET_EXEC)
    {
      error (0, 0, "\"%s\" is not a shared library", name);
      goto error_out;
    }

  /* Allocate DSO structure. Leave place for additional 20 new section
     headers.  */
  dso = (DSO *)
	malloc (sizeof(DSO) + (ehdr.e_shnum + 20) * sizeof(GElf_Shdr)
		+ (ehdr.e_phnum + 1) * sizeof(GElf_Phdr));
  if (!dso)
    {
      error (0, ENOMEM, "Could not open DSO");
      goto error_out;
    }

  elf_flagelf (elf, ELF_C_SET, ELF_F_LAYOUT);

  memset (dso, 0, sizeof(DSO));
  dso->elf = elf;
  dso->ehdr = ehdr;
  dso->phdr = (GElf_Phdr *) &dso->shdr[ehdr.e_shnum + 20];
  for (i = 0; i < ehdr.e_phnum; i++)
    gelf_getphdr (elf, i, dso->phdr + i);
  dso->fd = fd;
  for (i = 0; i < ehdr.e_shnum; i++)
    gelfx_getshdr (elf, elf_getscn (elf, i), dso->shdr + i);

  for (plarch = __start_pl_arch; plarch < __stop_pl_arch; plarch++)
    if (plarch->class == ehdr.e_ident[EI_CLASS]
	&& plarch->machine == ehdr.e_machine)
      break;

  if (plarch == __stop_pl_arch)
    {
      error (0, 0, "\"%s\"'s architecture is not supported", name);
      goto error_out;
    }

  dso->arch = plarch;

  dso->base = ~(GElf_Addr) 0;
  dso->align = 0;
  dso->end = 0;
  for (i = 0; i < dso->ehdr.e_phnum; i++)
    if (dso->phdr[i].p_type == PT_LOAD)
      {
	GElf_Addr base, end;

	if (dso->phdr[i].p_align > dso->align)
	  dso->align = dso->phdr[i].p_align;
	base = dso->phdr[i].p_vaddr & ~(dso->phdr[i].p_align - 1);
	end = dso->phdr[i].p_vaddr + dso->phdr[i].p_memsz;
	if (base < dso->base)
	  dso->base = base;
	if (end > dso->end)
	  dso->end = end;
      }

  if (dso->base == ~(GElf_Addr) 0)
    {
      error (0, 0, "%s: cannot find loadable segment", name);
      goto error_out;
    }

  read_dynamic (dso);

  dso->filename = (const char *) strdup (name);
  dso->soname = dso->filename;
  if (dso->info[DT_STRTAB] && dso->info[DT_SONAME])
    {
      const char *soname;

      soname = get_data (dso, dso->info[DT_STRTAB] + dso->info[DT_SONAME],
			 NULL);
      if (soname && soname[0] != '\0')
	dso->soname = (const char *) strdup (soname);
    }
  return dso;

error_out:
  if (dso)
    {
      if (dso->soname != dso->filename)
	free ((char *) dso->soname);
      free ((char *) dso->filename);
      free (dso);
    }
  if (elf)
    elf_end (elf);
  if (fd != -1)
    close (fd);
  return NULL;
}

static int
adjust_symtab_section_indices (DSO *dso, int n, int old_shnum, int *old_to_new)
{
  Elf_Data *data = NULL;
  Elf_Scn *scn = elf_getscn (dso->elf, n);
  GElf_Sym sym;
  int changed = 0, ndx, maxndx;

  while ((data = elf_getdata (scn, data)) != NULL)
    {
      maxndx = data->d_size / dso->shdr[n].sh_entsize;
      for (ndx = 0; ndx < maxndx; ++ndx)
	{
	  gelfx_getsym (dso->elf, data, ndx, &sym);
	  if (sym.st_shndx > SHN_UNDEF && sym.st_shndx < SHN_LORESERVE)
	    {
	      if (sym.st_shndx >= old_shnum
		  || old_to_new[sym.st_shndx] == -1)
		{
		  if (! sym.st_size &&
		      sym.st_info == ELF32_ST_INFO (STB_LOCAL, STT_SECTION))
		    {
		      sym.st_info = ELF32_ST_INFO (STB_LOCAL, STT_NOTYPE);
		      sym.st_value = 0;
		      sym.st_shndx = SHN_UNDEF;
		      gelfx_update_sym (dso->elf, data, ndx, &sym);
		      changed = 1;
		    }
		  else
		    {
		      if (sym.st_shndx >= old_shnum)
			{
			  error (0, 0, "%s: Symbol section index outside of section numbers",
				 dso->filename);
			  return 1;
			}
		      error (0, 0, "%s: Section symbol points into has been removed",
			     dso->filename);
		      return 1;
		    }
		}
	      if (old_to_new[sym.st_shndx] != sym.st_shndx)
		{
		  changed = 1;
		  sym.st_shndx = old_to_new[sym.st_shndx];
		  gelfx_update_sym (dso->elf, data, ndx, &sym);
		}
	    }
	}
    }

  if (changed)
    elf_flagscn (scn, ELF_C_SET, ELF_F_DIRTY);

  return 0;
}

struct section_move *
init_section_move (DSO *dso)
{
  struct section_move *move;
  int i;

  move = malloc (sizeof (struct section_move)
		 + (dso->ehdr.e_shnum * 2 + 20) * sizeof (int));
  if (move == NULL)
    {
      error (0, ENOMEM, "%s: Could not move sections", dso->filename);
      return move;
    }
  move->old_shnum = dso->ehdr.e_shnum;
  move->new_shnum = dso->ehdr.e_shnum;
  move->old_to_new = (int *)(move + 1);
  move->new_to_old = move->old_to_new + move->new_shnum;
  for (i = 0; i < move->new_shnum; i++)
    {
      move->old_to_new[i] = i;
      move->new_to_old[i] = i;
    }
  return move;
}

void
add_section (struct section_move *move, int sec)
{
  int i;

  assert (move->new_shnum < move->old_shnum + 20);
  assert (sec <= move->new_shnum);

  memmove (move->new_to_old + sec + 1, move->new_to_old + sec,
	   (move->new_shnum - sec) * sizeof (int));
  ++move->new_shnum;
  move->new_to_old[sec] = -1;
  for (i = 1; i < move->old_shnum; i++)
    if (move->old_to_new[i] >= sec)
      ++move->old_to_new[i];
}

void
remove_section (struct section_move *move, int sec)
{
  int i;

  assert (sec < move->new_shnum);

  memmove (move->new_to_old + sec, move->new_to_old + sec + 1,
	   (move->new_shnum - sec - 1) * sizeof (int));
  --move->new_shnum;
  for (i = 1; i < move->old_shnum; i++)
    if (move->old_to_new[i] == sec)
      move->old_to_new[i] = -1;
    else if (move->old_to_new[i] > sec)
      --move->old_to_new[i];
}

int
reopen_dso (DSO *dso, struct section_move *move)
{
  char filename[strlen (dso->filename) + sizeof (".#prelink#")];
  int adddel = 0;
  int free_move = 0;
  Elf *elf = NULL;
  GElf_Ehdr ehdr;
  char *e_ident;
  int fd, i, j;

  if (move == NULL)
    {
      move = init_section_move (dso);
      if (move == NULL)
	return 1;
      free_move = 1;
    }
  else
    {
      assert (dso->ehdr.e_shnum == move->old_shnum);
    }

  sprintf (filename, "%s.#prelink#", dso->filename);

  fd = open (filename, O_RDWR|O_CREAT|O_EXCL, 0600);
  if (fd == -1)
    {
      if (errno == EEXIST)
	{
	  unlink (filename);
	  fd = open (filename, O_RDWR|O_CREAT|O_EXCL, 0600);
	}

      if (fd == -1)
	{
	  error (0, errno, "Could not create temporary file %s", filename);
	  goto error_out;
	}
    }

  elf = elf_begin (fd, ELF_C_WRITE, NULL);
  if (elf == NULL)
    {
      error (0, 0, "cannot open ELF file: %s", elf_errmsg (-1));
      goto error_out;

    }

  if ((e_ident = (char *) gelf_newehdr (elf, gelf_getclass (dso->elf))) == NULL
      /* This is here just for the gelfx wrapper, so that gelf_update_ehdr
	 already has the correct ELF class.  */
      || memcpy (e_ident, dso->ehdr.e_ident, EI_NIDENT) == NULL
      || gelf_update_ehdr (elf, &dso->ehdr) == 0
      || gelf_newphdr (elf, dso->ehdr.e_phnum) == 0)
    {
      error (0, 0, "Could not create new ELF headers");
      goto error_out;
    }
  ehdr = dso->ehdr;
  elf_flagelf (elf, ELF_C_SET, ELF_F_LAYOUT);
  for (i = 0; i < ehdr.e_phnum; ++i)
    gelf_update_phdr (elf, i, dso->phdr + i);

  for (i = 1; i < move->new_shnum; ++i)
    {
      Elf_Scn *scn;
      Elf_Data data, *data1, *data2;

      if (move->new_to_old[i] == -1)
	{
	  scn = elf_newscn (elf);
	  elf_newdata (scn);
	}
      else
	{
	  j = move->new_to_old[i];
	  scn = elf_newscn (elf);
	  gelfx_update_shdr (elf, scn, &dso->shdr[j]);
	  if (dso->shdr[j].sh_type == SHT_NOBITS)
	    {
	       data1 = elf_getdata (elf_getscn (dso->elf, j), NULL);
	       data2 = elf_newdata (scn);
	       memcpy (data2, data1, sizeof (*data1));
	    }
	  else
	    {
	      data.d_type = ELF_T_NUM;
	      data1 = NULL;
	      while ((data1 = elf_getdata (elf_getscn (dso->elf, j), data1))
		     != NULL)
		{
		  if (data.d_type == ELF_T_NUM)
		    data = *data1;
		  else if (data.d_type != data1->d_type
			   || data.d_version != data1->d_version)
		    abort ();
		  else
		    {
		      if (data1->d_off < data.d_off)
			{
			  data.d_size += data.d_off - data1->d_off;
			  data.d_off = data1->d_off;
			}
		      if (data1->d_off + data1->d_size
			  > data.d_off + data.d_size)
			data.d_size = data1->d_off + data1->d_size
				      - data.d_off;
		      if (data1->d_align > data.d_align)
			data.d_align = data1->d_align;
		    }
		}
	      if (data.d_type == ELF_T_NUM)
		{
		  assert (dso->shdr[j].sh_size == 0);
		  continue;
		}
	      data.d_buf = calloc (1, data.d_size);
	      if (data.d_buf == NULL)
		{
		  error (0, ENOMEM, "%s: Could not copy section", dso->filename);
		  goto error_out;
		}
	      data1 = NULL;
	      while ((data1 = elf_getdata (elf_getscn (dso->elf, j), data1))
		     != NULL)
		memcpy (data.d_buf + data1->d_off - data.d_off, data1->d_buf,
			data1->d_size);
	      data2 = elf_newdata (scn);
	      memcpy (data2, &data, sizeof (data));
	    }
	}
    }

  ehdr.e_shnum = move->new_shnum;
  dso->elfro = dso->elf;
  dso->elf = elf;
  dso->fdro = dso->fd;
  dso->fd = fd;
  dso->ehdr = ehdr;
  dso->lastscn = 0;
  elf = NULL;
  fd = -1;
  for (i = 1; i < move->old_shnum; i++)
    if (move->old_to_new[i] != i)
      {
	adddel = 1;
	break;
      }
  if (! adddel)
    for (i = 1; i < move->new_shnum; i++)
      if (move->new_to_old[i] != i)
	{
	  adddel = 1;
	  break;
	}

  for (i = 1; i < move->new_shnum; i++)
    {
      gelfx_getshdr (dso->elf, elf_getscn (dso->elf, i), dso->shdr + i);
      if (adddel && move->new_to_old[i] != -1)
	{
	  if (dso->shdr[i].sh_link)
	    {
	      if (move->old_to_new[dso->shdr[i].sh_link] == -1)
		{
		  error (0, 0, "Section sh_link points to has been removed");
		  goto error_out;
		}
	      dso->shdr[i].sh_link = move->old_to_new[dso->shdr[i].sh_link];
	    }
	  /* Only some section types use sh_info for section index.  */
	  if (dso->shdr[i].sh_info
	      && (dso->shdr[i].sh_type == SHT_REL
		  || dso->shdr[i].sh_type == SHT_RELA
		  || (dso->shdr[i].sh_flags & SHF_INFO_LINK)))
	    {
	      if (move->old_to_new[dso->shdr[i].sh_info] == -1)
		{
		  error (0, 0, "Section sh_info points to has been removed");
		  goto error_out;
		}
	      dso->shdr[i].sh_info = move->old_to_new[dso->shdr[i].sh_info];
	    }
	  if (dso->shdr[i].sh_type == SHT_SYMTAB
	      || dso->shdr[i].sh_type == SHT_DYNSYM)
	    {
	      if (adjust_symtab_section_indices (dso, i, move->old_shnum,
						 move->old_to_new))
		goto error_out;
	    }
	}
    }

  dso->ehdr.e_shstrndx = move->old_to_new[dso->ehdr.e_shstrndx];
  gelf_update_ehdr (dso->elf, &dso->ehdr);

  read_dynamic (dso);

  /* If shoff does not point after last section, we need to adjust the sections
     after it if we added or removed some sections.  */
  if (move->old_shnum != move->new_shnum
      && adjust_dso_nonalloc (dso, 0, dso->ehdr.e_shoff + 1,
			      ((long) move->new_shnum - (long) move->old_shnum)
			      * gelf_fsize (dso->elf, ELF_T_SHDR, 1,
					    EV_CURRENT)))
    goto error_out;

  if (free_move)
    free (move);
  return 0;

error_out:
  if (free_move)
    free (move);
  if (elf)
    elf_end (elf);
  if (fd != -1)
    close (fd);
  return 1;
}

static int
adjust_symtab (DSO *dso, int n, GElf_Addr start, GElf_Addr adjust)
{
  Elf_Data *data = NULL;
  Elf_Scn *scn = elf_getscn (dso->elf, n);
  GElf_Sym sym;
  int ndx, maxndx;

  while ((data = elf_getdata (scn, data)) != NULL)
    {
      maxndx = data->d_size / dso->shdr[n].sh_entsize;
      for (ndx = 0; ndx < maxndx; ++ndx)
	{
	  gelfx_getsym (dso->elf, data, ndx, &sym);
	  if (sym.st_shndx == SHN_ABS && sym.st_value != 0
	      && GELF_ST_TYPE (sym.st_info) <= STT_FUNC)
	    {
	      /* This is problematic.  How do we find out if
		 we should relocate this?  Assume we should.  */
	      if (sym.st_value >= start)
		{
		  sym.st_value += adjust;
		  gelfx_update_sym (dso->elf, data, ndx, &sym);
		}
	      continue;
	    }

	  if (sym.st_shndx <= SHN_UNDEF
	      || sym.st_shndx >= dso->ehdr.e_shnum)
	    continue;

	  if (! RELOCATE_SCN (dso->shdr[sym.st_shndx].sh_flags))
	    continue;

	  if (sym.st_value >= start)
	    {
	      sym.st_value += adjust;
	      gelfx_update_sym (dso->elf, data, ndx, &sym);
	    }
	}
    }

  elf_flagscn (scn, ELF_C_SET, ELF_F_DIRTY);
  return 0;
}

int
dso_is_rdwr (DSO *dso)
{
  return dso->elfro != NULL;
}

GElf_Addr
adjust_old_to_new (DSO *dso, GElf_Addr addr)
{
  int i;

  if (dso->adjust == NULL)
    return addr; /* Fast path.  */

  for (i = 0; i < dso->nadjust; i++)
    if (addr >= dso->adjust[i].start)
      return addr + dso->adjust[i].adjust;

  return addr;
}

GElf_Addr
adjust_new_to_old (DSO *dso, GElf_Addr addr)
{
  int i;

  if (dso->adjust == NULL)
    return addr; /* Fast path.  */

  for (i = 0; i < dso->nadjust; i++)
    if (addr >= dso->adjust[i].start + dso->adjust[i].adjust)
      return addr - dso->adjust[i].adjust;

  return addr;
}

static int
adjust_dynamic (DSO *dso, int n, GElf_Addr start, GElf_Addr adjust)
{
  Elf_Data *data = NULL;
  Elf_Scn *scn = elf_getscn (dso->elf, n);
  GElf_Dyn dyn;
  int ndx, maxndx;

  while ((data = elf_getdata (scn, data)) != NULL)
    {
      maxndx = data->d_size / dso->shdr[n].sh_entsize;
      for (ndx = 0; ndx < maxndx; ++ndx)
	{
	  gelfx_getdyn (dso->elf, data, ndx, &dyn);
	  if (dso->arch->adjust_dyn (dso, n, &dyn, start, adjust) == 0)
	    switch (dyn.d_tag)
	      {
	      default:
		if (dyn.d_tag < DT_VALRNGLO || dyn.d_tag > DT_VALRNGHI)
		  break;
		/* FALLTHROUGH */
	      case DT_INIT:
	      case DT_FINI:
	      case DT_HASH:
	      case DT_STRTAB:
	      case DT_SYMTAB:
	      case DT_JMPREL:
	      case DT_REL:
	      case DT_RELA:
	      case DT_INIT_ARRAY:
	      case DT_FINI_ARRAY:
	      case DT_PREINIT_ARRAY:
	      case DT_VERDEF:
	      case DT_VERNEED:
	      case DT_VERSYM:
	      case DT_PLTGOT:
		if (dyn.d_un.d_ptr >= start)
		  {
		    dyn.d_un.d_ptr += adjust;
		    gelfx_update_dyn (dso->elf, data, ndx, &dyn);
		  }
		break;
	      }
	  else
	    gelfx_update_dyn (dso->elf, data, ndx, &dyn);
	}
    }

  elf_flagscn (scn, ELF_C_SET, ELF_F_DIRTY);

  /* Update the cached dynamic info as well.  */
  read_dynamic (dso);
  return 0;
}

int
addr_to_sec (DSO *dso, GElf_Addr addr)
{
  GElf_Shdr *shdr;
  int i;

  shdr = &dso->shdr[dso->lastscn];
  for (i = -1; i < dso->ehdr.e_shnum; shdr = &dso->shdr[++i])
    if (RELOCATE_SCN (shdr->sh_flags)
	&& shdr->sh_addr <= addr && shdr->sh_addr + shdr->sh_size > addr)
      {
	if (i != -1)
	  dso->lastscn = i;
	return dso->lastscn;
      }

  return -1;
}

static int
adjust_rel (DSO *dso, int n, GElf_Addr start, GElf_Addr adjust)
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

	  dso->arch->adjust_rel (dso, &rel, start, adjust);
	  addr_adjust (rel.r_offset, start, adjust);
	  gelfx_update_rel (dso->elf, data, ndx, &rel);
	}
    }

  elf_flagscn (scn, ELF_C_SET, ELF_F_DIRTY);
  return 0;
}

static int
adjust_rela (DSO *dso, int n, GElf_Addr start, GElf_Addr adjust)
{
  Elf_Data *data = NULL;
  Elf_Scn *scn = elf_getscn (dso->elf, n);
  GElf_Rela rela;
  int sec, ndx, maxndx;

  while ((data = elf_getdata (scn, data)) != NULL)
    {
      maxndx = data->d_size / dso->shdr[n].sh_entsize;
      for (ndx = 0; ndx < maxndx; ++ndx)
	{
	  gelfx_getrela (dso->elf, data, ndx, &rela);
	  sec = addr_to_sec (dso, rela.r_offset);
	  if (sec == -1)
	    continue;

	  dso->arch->adjust_rela (dso, &rela, start, adjust);
	  addr_adjust (rela.r_offset, start, adjust);
	  gelfx_update_rela (dso->elf, data, ndx, &rela);
	}
    }

  elf_flagscn (scn, ELF_C_SET, ELF_F_DIRTY);
  return 0;
}

int
adjust_dso_nonalloc (DSO *dso, int first, GElf_Addr start, GElf_Addr adjust)
{
  int i;

  for (i = 1; i < dso->ehdr.e_shnum; i++)
    {
      if (RELOCATE_SCN (dso->shdr[i].sh_flags))
	continue;

      if ((dso->shdr[i].sh_offset > start
	   || (dso->shdr[i].sh_offset == start && i >= first))
	  && (adjust & (dso->shdr[i].sh_addralign - 1)))
	adjust = (adjust + dso->shdr[i].sh_addralign - 1)
		 & ~(dso->shdr[i].sh_addralign - 1);
    }

  if (dso->ehdr.e_shoff >= start)
    {
      GElf_Addr shdralign = gelf_fsize (dso->elf, ELF_T_ADDR, 1, EV_CURRENT);

      if (adjust & (shdralign - 1))
	adjust = (adjust + shdralign - 1) & ~(shdralign - 1);
      dso->ehdr.e_shoff += adjust;
      gelf_update_ehdr (dso->elf, &dso->ehdr);
      elf_flagehdr (dso->elf, ELF_C_SET, ELF_F_DIRTY);
    }

  for (i = 1; i < dso->ehdr.e_shnum; i++)
    {
      if (RELOCATE_SCN (dso->shdr[i].sh_flags))
	continue;

      if (dso->shdr[i].sh_offset > start
	  || (dso->shdr[i].sh_offset == start && i >= first))
	{
	  Elf_Scn *scn = elf_getscn (dso->elf, i);

	  dso->shdr[i].sh_offset += adjust;
	  gelfx_update_shdr (dso->elf, scn, dso->shdr + i);
	  elf_flagshdr (scn, ELF_C_SET, ELF_F_DIRTY);
	}
    }
  return 0;
}

/* Add ADJUST to all addresses above START.  */
int
adjust_dso (DSO *dso, GElf_Addr start, GElf_Addr adjust)
{
  int i;

  if (dso->ehdr.e_entry >= start)
    {
      dso->ehdr.e_entry += adjust;
      gelf_update_ehdr (dso->elf, &dso->ehdr);
      elf_flagehdr (dso->elf, ELF_C_SET, ELF_F_DIRTY);
    }

  for (i = 0; i < dso->ehdr.e_phnum; i++)
    {
      if (! start)
	{
	  dso->phdr[i].p_vaddr += adjust;
	  dso->phdr[i].p_paddr += adjust;
	}
      else if (start <= dso->phdr[i].p_vaddr)
	{
	  dso->phdr[i].p_vaddr += adjust;
	  dso->phdr[i].p_paddr += adjust;
	  dso->phdr[i].p_offset += adjust;
	}
      else if (start < dso->phdr[i].p_vaddr + dso->phdr[i].p_filesz)
	{
	  dso->phdr[i].p_filesz += adjust;
	  dso->phdr[i].p_memsz += adjust;
	}
      else if (start < dso->phdr[i].p_vaddr + dso->phdr[i].p_filesz)
	dso->phdr[i].p_memsz += adjust;
      else
	continue;
      gelf_update_phdr (dso->elf, i, dso->phdr + i);
    }
  elf_flagphdr (dso->elf, ELF_C_SET, ELF_F_DIRTY);

  for (i = 1; i < dso->ehdr.e_shnum; i++)
    {
      const char *name;

      switch (dso->shdr[i].sh_type)
	{
	case SHT_PROGBITS:
	  name = strptr (dso, dso->ehdr.e_shstrndx, dso->shdr[i].sh_name);
	  if (strcmp (name, ".stab") == 0
	      && adjust_stabs (dso, i, start, adjust))
	    return 1;
	  if (strcmp (name, ".debug_info") == 0
	      && adjust_dwarf2 (dso, i, start, adjust))
	    return 1;
	  break;
	case SHT_HASH:
	case SHT_NOBITS:
	case SHT_STRTAB:
	  break;
	case SHT_SYMTAB:
	case SHT_DYNSYM:
	  if (adjust_symtab (dso, i, start, adjust))
	    return 1;
	  break;
	case SHT_DYNAMIC:
	  if (adjust_dynamic (dso, i, start, adjust))
	    return 1;
	  break;
	case SHT_REL:
	  if (adjust_rel (dso, i, start, adjust))
	    return 1;
	  break;
	case SHT_RELA:
	  if (adjust_rela (dso, i, start, adjust))
	    return 1;
	  break;
	}
    }

  for (i = 0; i < dso->ehdr.e_shnum; i++)
    {
      if (RELOCATE_SCN (dso->shdr[i].sh_flags))
	{
	  if (dso->shdr[i].sh_addr >= start)
	    {
	      Elf_Scn *scn = elf_getscn (dso->elf, i);

	      dso->shdr[i].sh_addr += adjust;
	      if (start)
		dso->shdr[i].sh_offset += adjust;
	      gelfx_update_shdr (dso->elf, scn, dso->shdr + i);
	      elf_flagshdr (scn, ELF_C_SET, ELF_F_DIRTY);
	    }
	}
    }

  addr_adjust (dso->base, start, adjust);
  addr_adjust (dso->end, start, adjust);

  if (start)
    {
      start = adjust_new_to_old (dso, start);
      for (i = 0; i < dso->nadjust; i++)
	if (start < dso->adjust[i].start)
	  dso->adjust[i].adjust += adjust;
	else
	  break;
      if (i < dso->nadjust && start == dso->adjust[i].start)
	dso->adjust[i].adjust += adjust;
      else
	{
	  dso->adjust =
	    realloc (dso->adjust, (dso->nadjust + 1) * sizeof (*dso->adjust));
	  if (dso->adjust == NULL)
	    {
	      error (0, ENOMEM, "Cannot record the list of adjustements being made");
	      return 1;
	    }
	  memmove (dso->adjust + i + 1, dso->adjust + i, dso->nadjust - i);
	  dso->adjust[i].start = start;
	  dso->adjust[i].adjust = adjust;
	  ++dso->nadjust;
	}
    }

  return start ? adjust_dso_nonalloc (dso, 0, 0, adjust) : 0;
}

int
strtabfind (DSO *dso, int strndx, const char *name)
{
  Elf_Scn *scn;
  Elf_Data *data;
  const char *p, *q, *r;
  size_t len = strlen (name);

  if (dso->shdr[strndx].sh_type != SHT_STRTAB)
    return 0;

  scn = elf_getscn (dso->elf, strndx);
  data = elf_getdata (scn, NULL);
  assert (elf_getdata (scn, data) == NULL);
  assert (data->d_off == 0);
  assert (data->d_size == dso->shdr[strndx].sh_size);
  q = data->d_buf + data->d_size;
  for (p = data->d_buf; p < q; p = r + 1)
    {
      r = strchr (p, '\0');
      if (r - p >= len && memcmp (r - len, name, len) == 0)
	return (r - (const char *) data->d_buf) - len;
    }

  return 0;
}

int
shstrtabadd (DSO *dso, const char *name)
{
  Elf_Scn *scn;
  Elf_Data *data;
  GElf_Addr adjust;
  const char *p, *q, *r;
  size_t len = strlen (name), align;
  int ret;

  scn = elf_getscn (dso->elf, dso->ehdr.e_shstrndx);
  data = elf_getdata (scn, NULL);
  assert (elf_getdata (scn, data) == NULL);
  assert (data->d_off == 0);
  assert (data->d_size == dso->shdr[dso->ehdr.e_shstrndx].sh_size);
  q = data->d_buf + data->d_size;
  for (p = data->d_buf; p < q; p = r + 1)
    {
      r = strchr (p, '\0');
      if (r - p >= len && memcmp (r - len, name, len) == 0)
	return (r - (const char *) data->d_buf) - len;
    }

  data->d_buf = realloc (data->d_buf, data->d_size + len + 1);
  if (data->d_buf == NULL)
    {
      error (0, ENOMEM, "Cannot add new section name %s", name);
      return 0;
    }

  memcpy (data->d_buf + data->d_size, name, len + 1);
  ret = data->d_size;
  data->d_size += len + 1;
  align = gelf_fsize (dso->elf, ELF_T_ADDR, 1, EV_CURRENT);
  adjust = (len + 1 + align - 1) & ~(align - 1);
  if (adjust_dso_nonalloc (dso, 0,
			   dso->shdr[dso->ehdr.e_shstrndx].sh_offset
			   + dso->shdr[dso->ehdr.e_shstrndx].sh_size,
			   adjust))
    return 0;
  dso->shdr[dso->ehdr.e_shstrndx].sh_size += len + 1;
  return ret;
}

int
relocate_dso (DSO *dso, GElf_Addr base)
{
  /* Check if it is already relocated.  */
  if (dso->base == base)
    return 0;

  if (! dso_is_rdwr (dso))
    {
      if (reopen_dso (dso, NULL))
	return 1;	
    }

  return adjust_dso (dso, 0, base - dso->base);
}

static int
close_dso_1 (DSO *dso)
{
  if (dso_is_rdwr (dso))
    {
      int i;

      for (i = 1; i < dso->ehdr.e_shnum; ++i)
	{
	  Elf_Scn *scn = elf_getscn (dso->elf, i);
	  Elf_Data *data = NULL;

	  while ((data = elf_getdata (scn, data)) != NULL)
	    {
	      free (data->d_buf);
	      data->d_buf = NULL;
	    }
	}
    }

  elf_end (dso->elf);
  close (dso->fd);
  if (dso->elfro)
    {
      elf_end (dso->elfro);
      close (dso->fdro);
    }
  if (dso->filename != dso->soname)
    free ((char *) dso->soname);
  free ((char *) dso->filename);
  free (dso->adjust);
  free (dso->undo.d_buf);
  free (dso);
  return 0;
}

int
close_dso (DSO *dso)
{
  int rdwr = dso_is_rdwr (dso);

  if (rdwr)
    {
      char *name;
      size_t len = strlen (dso->filename);
      name = alloca (len + sizeof (".#prelink#"));
      memcpy (name, dso->filename, len);
      memcpy (name + len, ".#prelink#", sizeof (".#prelink#"));
      unlink (name);
    }
  close_dso_1 (dso);
  return 0;
}

int
update_dso (DSO *dso)
{
  int rdwr = dso_is_rdwr (dso);

  if (rdwr)
    {
      char *name1, *name2;
      size_t len = strlen (dso->filename);
      struct utimbuf u;
      struct stat64 st;
      int i;

      if (check_dso (dso))
	{
	  close_dso (dso);
	  return 1;
	}

      name1 = alloca (len + 1);
      name2 = alloca (len + sizeof (".#prelink#"));
      memcpy (name1, dso->filename, len + 1);
      memcpy (name2, dso->filename, len);
      memcpy (name2 + len, ".#prelink#", sizeof (".#prelink#"));
      gelf_update_ehdr (dso->elf, &dso->ehdr);
      for (i = 0; i < dso->ehdr.e_phnum; ++i)
	gelf_update_phdr (dso->elf, i, dso->phdr + i);
      for (i = 0; i < dso->ehdr.e_shnum; ++i)
	gelfx_update_shdr (dso->elf, elf_getscn (dso->elf, i), dso->shdr + i);
      if (elf_update (dso->elf, ELF_C_WRITE) == -1)
	{
	  error (0, 0, "Could not write %s: %s", dso->filename,
		 elf_errmsg (-1));
	  close_dso (dso);
	  return 1;
	}
      if (fstat64 (dso->fdro, &st) < 0)
	{
	  error (0, errno, "Could not stat %s", dso->filename);
	  close_dso (dso);
	  return 1;
	}
      if (fchown (dso->fd, st.st_uid, st.st_gid) < 0
	  || fchmod (dso->fd, st.st_mode & 07777) < 0)
	{
	  error (0, errno, "Could not set %s owner or mode", dso->filename);
	  close_dso (dso);
	  return 1;
	}
      close_dso_1 (dso);
      u.actime = time (NULL);
      u.modtime = st.st_mtime;
      utime (name2, &u);
      if (rename (name2, name1))
	{
	  error (0, errno, "Could not rename temporary to %s",
		 name1);
	  return 1;
	}
    }
  else
    close_dso_1 (dso);
  
  return 0;
}
