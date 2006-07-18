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

#include "prelink.h"

unsigned char *
get_data (DSO *dso, GElf_Addr addr, int *secp)
{
  int sec = addr_to_sec (dso, addr);
  Elf_Data *data = NULL;

  if (sec == -1)
    return NULL;

  if (secp)
    *secp = sec;

  addr -= dso->shdr[sec].sh_addr;
  while ((data = elf_getdata (elf_getscn (dso->elf, sec), data)) != NULL)
    if (data->d_off <= addr && data->d_off + data->d_size > addr)
      return (unsigned char *) data->d_buf + (addr - data->d_off);

  return NULL;
}

uint8_t
read_u8 (DSO *dso, GElf_Addr addr)
{
  unsigned char *data = get_data (dso, addr, NULL);

  if (data == NULL)
    return 0;

  return data[0];
}

uint16_t
read_ule16 (DSO *dso, GElf_Addr addr)
{
  unsigned char *data = get_data (dso, addr, NULL);

  if (data == NULL)
    return 0;

  return data[0] | (data[1] << 8);
}

uint16_t
read_ube16 (DSO *dso, GElf_Addr addr)
{
  unsigned char *data = get_data (dso, addr, NULL);

  if (data == NULL)
    return 0;

  return data[1] | (data[0] << 8);
}

uint32_t
read_ule32 (DSO *dso, GElf_Addr addr)
{
  unsigned char *data = get_data (dso, addr, NULL);

  if (data == NULL)
    return 0;

  return data[0] | (data[1] << 8) | (data[2] << 16) | (data[3] << 24);
}

uint32_t
read_ube32 (DSO *dso, GElf_Addr addr)
{
  unsigned char *data = get_data (dso, addr, NULL);

  if (data == NULL)
    return 0;

  return data[3] | (data[2] << 8) | (data[1] << 16) | (data[0] << 24);
}

uint64_t
read_ule64 (DSO *dso, GElf_Addr addr)
{
  unsigned char *data = get_data (dso, addr, NULL);

  if (data == NULL)
    return 0;

  return (data[0] | (data[1] << 8) | (data[2] << 16) | (data[3] << 24))
	 || (((uint64_t)(data[4] | (data[5] << 8) | (data[6] << 16)
			 | (data[7] << 24))) << 32);
}

uint64_t
read_ube64 (DSO *dso, GElf_Addr addr)
{
  unsigned char *data = get_data (dso, addr, NULL);

  if (data == NULL)
    return 0;

  return (data[7] | (data[6] << 8) | (data[5] << 16) | (data[4] << 24))
	 || (((uint64_t)(data[3] | (data[2] << 8) | (data[1] << 16)
			 | (data[0] << 24))) << 32);
}

int
write_8 (DSO *dso, GElf_Addr addr, uint8_t val)
{
  int sec;
  unsigned char *data = get_data (dso, addr, &sec);

  if (data == NULL)
    return -1;

  data[0] = val;
  elf_flagscn (elf_getscn (dso->elf, sec), ELF_C_SET, ELF_F_DIRTY);
  return 0;
}

int
write_le16 (DSO *dso, GElf_Addr addr, uint16_t val)
{
  int sec;
  unsigned char *data = get_data (dso, addr, &sec);

  if (data == NULL)
    return -1;

  data[0] = val;
  data[1] = val >> 8;
  elf_flagscn (elf_getscn (dso->elf, sec), ELF_C_SET, ELF_F_DIRTY);
  return 0;
}

int
write_be16 (DSO *dso, GElf_Addr addr, uint16_t val)
{
  int sec;
  unsigned char *data = get_data (dso, addr, &sec);

  if (data == NULL)
    return -1;

  data[1] = val;
  data[0] = val >> 8;
  elf_flagscn (elf_getscn (dso->elf, sec), ELF_C_SET, ELF_F_DIRTY);
  return 0;
}

int
write_le32 (DSO *dso, GElf_Addr addr, uint32_t val)
{
  int sec;
  unsigned char *data = get_data (dso, addr, &sec);

  if (data == NULL)
    return -1;

  data[0] = val;
  data[1] = val >> 8;
  data[2] = val >> 16;
  data[3] = val >> 24;
  elf_flagscn (elf_getscn (dso->elf, sec), ELF_C_SET, ELF_F_DIRTY);
  return 0;
}

int
write_be32 (DSO *dso, GElf_Addr addr, uint32_t val)
{
  int sec;
  unsigned char *data = get_data (dso, addr, &sec);

  if (data == NULL)
    return -1;

  data[3] = val;
  data[2] = val >> 8;
  data[1] = val >> 16;
  data[0] = val >> 24;
  elf_flagscn (elf_getscn (dso->elf, sec), ELF_C_SET, ELF_F_DIRTY);
  return 0;
}

int
write_le64 (DSO *dso, GElf_Addr addr, uint64_t val)
{
  int sec;
  unsigned char *data = get_data (dso, addr, &sec);

  if (data == NULL)
    return -1;

  data[0] = val;
  data[1] = val >> 8;
  data[2] = val >> 16;
  data[3] = val >> 24;
  data[4] = val >> 32;
  data[5] = val >> 40;
  data[6] = val >> 48;
  data[7] = val >> 56;
  elf_flagscn (elf_getscn (dso->elf, sec), ELF_C_SET, ELF_F_DIRTY);
  return 0;
}

int
write_be64 (DSO *dso, GElf_Addr addr, uint64_t val)
{
  int sec;
  unsigned char *data = get_data (dso, addr, &sec);

  if (data == NULL)
    return -1;

  data[7] = val;
  data[6] = val >> 8;
  data[5] = val >> 16;
  data[4] = val >> 24;
  data[3] = val >> 32;
  data[2] = val >> 40;
  data[1] = val >> 48;
  data[0] = val >> 56;
  elf_flagscn (elf_getscn (dso->elf, sec), ELF_C_SET, ELF_F_DIRTY);
  return 0;
}

const char *
strptr (DSO *dso, int sec, off_t offset)
{
  Elf_Scn *scn;
  Elf_Data *data;

  scn = elf_getscn (dso->elf, sec);
  if (offset >= 0 && offset < dso->shdr[sec].sh_size)
    {
      data = NULL;
      while ((data = elf_getdata (scn, data)) != NULL)
	{
	  if (data->d_buf
	      && offset >= data->d_off
	      && offset < data->d_off + data->d_size)
	    return (const char *) data->d_buf + (offset - data->d_off);
	}
    }

  return NULL;
}
