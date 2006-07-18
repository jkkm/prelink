/* Generic ELF wrapper for libelf which does not support gelf_ API.
   Copyright (C) 2001 Red Hat, Inc.
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

#ifndef GELFX_H
#define	GELFX_H

#include <libelf.h>
#include <gelf.h>

#ifndef GELF_ST_BIND

typedef Elf64_Half	GElf_Half;
typedef Elf64_Word	GElf_Word;
typedef	Elf64_Sword	GElf_Sword;
typedef Elf64_Xword	GElf_Xword;
typedef	Elf64_Sxword	GElf_Sxword;
typedef Elf64_Addr	GElf_Addr;
typedef Elf64_Off	GElf_Off;
typedef Elf64_Ehdr	GElf_Ehdr;
typedef Elf64_Shdr	GElf_Shdr;
typedef Elf64_Section	GElf_Section;
typedef Elf64_Sym	GElf_Sym;
typedef Elf64_Rel	GElf_Rel;
typedef Elf64_Rela	GElf_Rela;
typedef Elf64_Phdr	GElf_Phdr;
typedef Elf64_Dyn	GElf_Dyn;
#define GELF_ST_BIND	ELF64_ST_BIND
#define GELF_ST_TYPE	ELF64_ST_TYPE
#define GELF_ST_INFO	ELF64_ST_INFO
#define GELF_R_SYM	ELF64_R_SYM
#define GELF_R_TYPE	ELF64_R_TYPE
#define GELF_R_INFO	ELF64_R_INFO

extern int gelf_getclass (Elf *);
extern size_t gelf_fsize (Elf *, Elf_Type, size_t, unsigned);
extern GElf_Ehdr *gelf_getehdr (Elf *, GElf_Ehdr *);
extern int gelf_update_ehdr (Elf *, GElf_Ehdr *);
extern unsigned long gelf_newehdr (Elf *, int);
extern GElf_Phdr *gelf_getphdr (Elf *, int, GElf_Phdr *);
extern int gelf_update_phdr (Elf *, int, GElf_Phdr *);
extern unsigned long gelf_newphdr (Elf *, size_t);
extern Elf_Data *gelf_xlatetom (Elf *, Elf_Data *, const Elf_Data *, unsigned);
extern Elf_Data *gelf_xlatetof (Elf *, Elf_Data *, const Elf_Data *, unsigned);
/* The gelf_ equivalents of these functions only provide Elf_Scn resp.
   Elf_Data pointers, without changing the underlying libelf implementation
   it is either impossible to get Elf * pointer from that or it requires
   internal knowledge about the libelf implementation.  */
extern GElf_Shdr *gelfx_getshdr (Elf *, Elf_Scn *, GElf_Shdr *);
extern int gelfx_update_shdr (Elf *, Elf_Scn *, GElf_Shdr *);
extern GElf_Sym *gelfx_getsym (Elf *, Elf_Data *, int, GElf_Sym *);
extern int gelfx_update_sym (Elf *, Elf_Data *, int, GElf_Sym *);
extern GElf_Dyn *gelfx_getdyn (Elf *, Elf_Data *, int, GElf_Dyn *);
extern int gelfx_update_dyn (Elf *, Elf_Data *, int, GElf_Dyn *);
extern GElf_Rel *gelfx_getrel (Elf *, Elf_Data *, int, GElf_Rel *);
extern GElf_Rela *gelfx_getrela (Elf *, Elf_Data *, int, GElf_Rela *);
extern int gelfx_update_rel (Elf *, Elf_Data *, int, GElf_Rel *);
extern int gelfx_update_rela (Elf *, Elf_Data *, int, GElf_Rela *);

#else

/* If we have gelf.h, just provide these wrappers.  */

#define gelfx_getshdr(elf,scn,shdr) gelf_getshdr(scn,shdr)
#define gelfx_update_shdr(elf,scn,shdr) gelf_update_shdr(scn,shdr)
#define gelfx_getsym(elf,data,x) gelf_getsym(data,x)
#define gelfx_update_sym(elf,data,ndx,x) gelf_update_sym(data,ndx,x)
#define gelfx_getdyn(elf,data,ndx,x) gelf_getdyn(data,ndx,x)
#define gelfx_update_dyn(elf,data,ndx,x) gelf_update_dyn(data,ndx,x)
#define gelfx_getrel(elf,data,ndx,x) gelf_getrel(data,ndx,x)
#define gelfx_update_rel(elf,data,ndx,x) gelf_update_rel(data,ndx,x)
#define gelfx_getrela(elf,data,ndx,x) gelf_getrela(data,ndx,x)
#define gelfx_update_rela(elf,data,ndx,x) gelf_update_rela(data,ndx,x)

#endif

#endif	/* GELFX_H */
