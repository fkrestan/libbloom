/*
 *  Copyright (c) 2016-2017, Jyri J. Virkki
 *  All rights reserved.
 *
 *  This file is under BSD license. See LICENSE file.
 */

#include <assert.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

#include "bloom.h"

#ifdef __linux
#include <sys/time.h>
#include <time.h>
#endif


/** ***************************************************************************
 * A few simple tests to check if it works at all.
 *
 * These are covered in the main test, repeated here just to create a test
 * executable using the static libbloom library to exercise it as well.
 *
 */
int main(int argc, char **argv)
{
  struct bloom bloom;
  struct bloom bloom2;

  printf("----- Basic tests with static library -----\n");
  assert(bloom_init(&bloom, 0, 1.0) == 1);
  assert(bloom_init(&bloom, 10, 0) == 1);
  assert(bloom.ready == 0);
  assert(bloom_add(&bloom, "hello world", 11) == -1);
  assert(bloom_check(&bloom, "hello world", 11) == -1);
  bloom_free(&bloom);

  assert(bloom_init(&bloom, 1002, 0.1) == 0);
  assert(bloom.ready == 1);
  bloom_print(&bloom);

  assert(bloom_check(&bloom, "hello world", 11) == 0);
  assert(bloom_add(&bloom, "hello world", 11) == 0);
  assert(bloom_check(&bloom, "hello world", 11) == 1);
  assert(bloom_add(&bloom, "hello world", 11) > 0);
  assert(bloom_add(&bloom, "hello", 5) == 0);
  assert(bloom_add(&bloom, "hello", 5) > 0);
  assert(bloom_check(&bloom, "hello", 5) == 1);
  bloom_free(&bloom);

  printf("----- Basic tests with static library - merge -----\n");
  assert(bloom_init(&bloom, 1002, 0.1) == 0);
  assert(bloom.ready == 1);

  assert(bloom2.ready != 1);
  assert(bloom_merge(&bloom, &bloom2) == -1);

  assert(bloom_init(&bloom2, 1003, 0.1) == 0);
  assert(bloom2.ready == 1);
  assert(bloom_merge(&bloom, &bloom2) == -2);
  bloom_free(&bloom2);

  assert(bloom_init(&bloom2, 1002, 0.2) == 0);
  assert(bloom2.ready == 1);
  assert(bloom_merge(&bloom, &bloom2) == -3);
  bloom_free(&bloom2);

  assert(bloom_init(&bloom2, 1002, 0.1) == 0);
  assert(bloom2.ready == 1);
  assert(bloom_add(&bloom, "hello world", 11) == 0);
  assert(bloom_add(&bloom, "hello", 5) == 0);
  assert(bloom_add(&bloom2, "hello world 2", 13) == 0);
  assert(bloom_add(&bloom2, "hello 2", 7) == 0);
  assert(bloom_merge(&bloom, &bloom2) == 0);
  assert(bloom_check(&bloom2, "hello world", 11) == 0);
  assert(bloom_check(&bloom2, "hello", 5) == 0);
  assert(bloom_check(&bloom2, "hello world 2", 13) == 1);
  assert(bloom_check(&bloom2, "hello 2", 7) == 1);
  assert(bloom_check(&bloom, "hello world", 11) == 1);
  assert(bloom_check(&bloom, "hello", 5) == 1);
  assert(bloom_check(&bloom, "hello world 2", 13) == 1);
  assert(bloom_check(&bloom, "hello 2", 7) == 1);
  bloom_print(&bloom);
  bloom_print(&bloom2);

  bloom_free(&bloom);
  bloom_free(&bloom2);

  printf("----- DONE Basic tests with static library -----\n");
}
