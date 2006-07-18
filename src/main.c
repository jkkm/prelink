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

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <locale.h>
#include <error.h>
#include <argp.h>
#include <stdlib.h>

#include "prelink.h"

#define PRELINK_CONF "/etc/prelink.conf"
#define PRELINK_CACHE "/etc/prelink.cache"

int all;
int force;
int verbose;
int print_cache;
int reloc_only;
int no_update;
const char *dynamic_linker;
const char *ld_library_path;
const char *prelink_conf = PRELINK_CONF;
const char *prelink_cache = PRELINK_CACHE;

const char *argp_program_version = "prelink 1.0";

const char *argp_program_bug_address = "<jakub@redhat.com>";
                        
static char argp_doc[] = "prelink -- program to relocate and prelink an ELF shared library";

#define OPT_DYNAMIC_LINKER	0x80
#define OPT_LD_LIBRARY_PATH	0x81

static struct argp_option options[] = {
  {"all",		'a', 0, 0,  "Prelink all binaries" },
  {"cache-file",	'C', "CACHE", 0, "Use CACHE as cache file" },
  {"config-file",	'f', "CONF", 0, "Use CONF as configuration file" },
  {"force",		'F', 0, 0,  "Force prelinking" },
  {"no-update",		'n', 0, 0,  "Don't update prelink cache" },
  {"print-cache",	'p', 0,	0,  "Print prelink cache" },
  {"reloc-only",	'r', 0, 0,  "Relocate only, don't prelink" },
  {"verbose",		'v', 0, 0,  "Produce verbose output" },
  {"dynamic-linker",	OPT_DYNAMIC_LINKER, "DYNAMIC_LINKER",
			        0,  "Special dynamic linker path" },
  {"ld-library-path",	OPT_LD_LIBRARY_PATH, "PATHLIST",
			        0,  "What LD_LIBRARY_PATH should be used" },
  { 0 }
};

static error_t
parse_opt (int key, char *arg, struct argp_state *state)
{
  switch (key)
    {
    case 'a':
      all = 1;
      break;
    case 'F':
      force = 1;
      break;
    case 'p':
      print_cache = 1;
      break;
    case 'v':
      verbose = 1;
      break;
    case 'r':
      reloc_only = 1;
      break;
    case 'n':
      no_update = 1;
      break;
    case 'C':
      prelink_cache = arg;
      break;
    case 'f':
      prelink_conf = arg;
      break;
    case OPT_DYNAMIC_LINKER:
      dynamic_linker = arg;
      break;
    case OPT_LD_LIBRARY_PATH:
      ld_library_path = arg;
      break;
    default:
      return ARGP_ERR_UNKNOWN;
    }
  return 0;
}

static struct argp argp = { options, parse_opt, 0, argp_doc };

int
main (int argc, char *argv[])
{
  int remaining, failures = 0;
  DSO *dso;

  setlocale (LC_ALL, "");

  argp_parse (&argp, argc, argv, 0, &remaining, 0);

  elf_version (EV_CURRENT);

  if (dynamic_linker == NULL)
    dynamic_linker = "/lib/ld-linux.so.2"; /* FIXME.  */

  if (all)
    {
      prelink_init_cache ();
      if (gather_config (prelink_conf))
        return EXIT_FAILURE;
      layout_libs ();
      return 0;
    }

  prelink_load_cache ();

  if (print_cache)
    {
      prelink_print_cache ();
      return 0;
    }

  if (remaining >= argc)
    error (1, 0, "No files given\n");

  while (remaining < argc)
    {
      dso = open_dso (argv[remaining++]);
      if (dso == NULL)
	continue;
      if (! reloc_only)
	if (prelink_prepare (dso))
	  {
	    close_dso (dso);
	    ++failures;
	    continue;
	  }
      if (dso->ehdr.e_type == ET_DYN
	  && relocate_dso (dso, prelink_find_base (dso)))
	{
	  close_dso (dso);
	  ++failures;
	  continue;
	}
      if (! reloc_only)
	if (prelink (dso))
	  {
	    close_dso (dso);
	    ++failures;
	    continue;
	  }
      update_dso (dso);
    }

  if (! no_update && ! failures)
    prelink_save_cache ();
  return 0;
}
