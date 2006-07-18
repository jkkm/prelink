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
GElf_Addr reloc_base;
int no_update;
int random_base;
int conserve_memory;
int libs_only;
int dry_run;
int dereference;
int one_file_system;
const char *dynamic_linker;
const char *ld_library_path;
const char *prelink_conf = PRELINK_CONF;
const char *prelink_cache = PRELINK_CACHE;

const char *argp_program_version = "prelink 1.0";

const char *argp_program_bug_address = "<jakub@redhat.com>";
                        
static char argp_doc[] = "prelink -- program to relocate and prelink an ELF shared library";

#define OPT_DYNAMIC_LINKER	0x80
#define OPT_LD_LIBRARY_PATH	0x81
#define OPT_LIBS_ONLY		0x82

static struct argp_option options[] = {
  {"all",		'a', 0, 0,  "Prelink all binaries" },
  {"cache-file",	'C', "CACHE", 0, "Use CACHE as cache file" },
  {"config-file",	'c', "CONF", 0, "Use CONF as configuration file" },
  {"force",		'f', 0, 0,  "Force prelinking" },
  {"dereference",	'h', 0, 0,  "Follow symlinks when processing directory trees from command line" },
  {"one-file-system",	'l', 0, 0,  "Stay in local file system when processing directories from command line" },
  {"conserve-memory",	'm', 0, 0,  "Allow libraries to overlap as long as they never appear in the same program" },
  {"no-update-cache",	'N', 0, 0,  "Don't update prelink cache" },
  {"dry-run",		'n', 0, 0,  "Don't actually prelink anything" },
  {"print-cache",	'p', 0,	0,  "Print prelink cache" },
  {"random",		'R', 0, 0,  "Choose random base for libraries" },
  {"reloc-only",	'r', "BASE_ADDRESS", 0,  "Relocate library to given address, don't prelink" },
  {"verbose",		'v', 0, 0,  "Produce verbose output" },
  {"dynamic-linker",	OPT_DYNAMIC_LINKER, "DYNAMIC_LINKER",
			        0,  "Special dynamic linker path" },
  {"ld-library-path",	OPT_LD_LIBRARY_PATH, "PATHLIST",
			        0,  "What LD_LIBRARY_PATH should be used" },
  {"libs-only",		OPT_LIBS_ONLY, 0, 0, "Prelink only libraries, no binaries" },
  { 0 }
};

static error_t
parse_opt (int key, char *arg, struct argp_state *state)
{
  char *endarg;

  switch (key)
    {
    case 'a':
      all = 1;
      break;
    case 'f':
      force = 1;
      break;
    case 'p':
      print_cache = 1;
      break;
    case 'v':
      verbose = 1;
      break;
    case 'R':
      random_base = 1;
      break;
    case 'r':
      reloc_only = 1;
      reloc_base = strtoull (arg, &endarg, 0);
      if (endarg != strchr (arg, '\0'))
	error (EXIT_FAILURE, 0, "-r option requires numberic argument");
      break;
    case 'h':
      dereference = 1;
      break;
    case 'l':
      one_file_system = 1;
      break;
    case 'm':
      conserve_memory = 1;
      break;
    case 'N':
      no_update = 1;
      break;
    case 'n':
      dry_run = 1;
      break;
    case 'C':
      prelink_cache = arg;
      break;
    case 'c':
      prelink_conf = arg;
      break;
    case OPT_DYNAMIC_LINKER:
      dynamic_linker = arg;
      break;
    case OPT_LD_LIBRARY_PATH:
      ld_library_path = arg;
      break;
    case OPT_LIBS_ONLY:
      libs_only = 1;
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

  setlocale (LC_ALL, "");

  argp_parse (&argp, argc, argv, 0, &remaining, 0);

  elf_version (EV_CURRENT);

  if (dynamic_linker == NULL)
    dynamic_linker = "/lib/ld-linux.so.2"; /* FIXME.  */

  if (ld_library_path == NULL)
    ld_library_path = getenv ("LD_LIBRARY_PATH");

  if (all && reloc_only)
    error (EXIT_FAILURE, 0, "--all and --reloc-only options are incompatible");

  prelink_init_cache ();

  if (print_cache)
    {
      prelink_load_cache ();
      prelink_print_cache ();
      return 0;
    }

  if (remaining == argc && ! all)
    error (EXIT_FAILURE, 0, "no files given and --all not used");

  if (reloc_only)
    {
      while (remaining < argc)
	{
	  DSO *dso = open_dso (argv[remaining++]);

	  if (dso == NULL)
	    {
	      ++failures;
	      continue;
	    }

	  if (dso->ehdr.e_type != ET_DYN)
	    {
	      ++failures;
	      error (0, 0, "%s is not a shared library", dso->filename);
	      continue;
	    }

	  if (relocate_dso (dso, reloc_base))
	    {
	      ++failures;
	      close_dso (dso);
	      continue;
	    }

	  if (dso->info_DT_CHECKSUM && ! prelink_set_checksum (dso))
	    {
	      ++failures;
	      close_dso (dso);
	      continue;
	    }

	  if (update_dso (dso))
	    ++failures;
	}

      return failures;
    }

  if (gather_config (prelink_conf))
    return EXIT_FAILURE;

  while (remaining < argc)
    if (gather_object (argv[remaining++], dereference, one_file_system))
      return EXIT_FAILURE;

  if (! all)
    prelink_load_cache ();

  layout_libs ();
  prelink_all ();

  if (! no_update && ! dry_run)
    prelink_save_cache (all);
  return 0;
}
