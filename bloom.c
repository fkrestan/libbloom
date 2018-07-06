/*
 *  Copyright (c) 2012-2017, Jyri J. Virkki
 *  All rights reserved.
 *
 *  This file is under BSD license. See LICENSE file.
 */

/*
 * Refer to bloom.h for documentation on the public interfaces.
 */

#include <arpa/inet.h>
#include <assert.h>
#include <fcntl.h>
#include <math.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "bloom.h"
#include "murmurhash2.h"

#define MAKESTRING(n) STRING(n)
#define STRING(n) #n

inline static int test_bit_set_bit(uint8_t * buf,
                                   unsigned int x, int set_bit)
{
  unsigned int byte = x >> 3;
  uint8_t c = buf[byte];        // expensive memory access
  unsigned int mask = 1 << (x % 8);

  if (c & mask) {
    return 1;
  } else {
    if (set_bit) {
      buf[byte] = c | mask;
    }
    return 0;
  }
}


static int bloom_check_add(struct bloom * bloom,
                           const void * buffer, int32_t len, int add)
{
  if (bloom->ready == 0) {
    printf("bloom at %p not initialized!\n", (void *)bloom);
    return -1;
  }

  int hits = 0;
  register unsigned int a = murmurhash2(buffer, len, 0x9747b28c);
  register unsigned int b = murmurhash2(buffer, len, a);
  register unsigned int x;
  register unsigned int i;

  for (i = 0; i < bloom->hashes; i++) {
    x = (a + i*b) % bloom->bits;
    if (test_bit_set_bit(bloom->bf, x, add)) {
      hits++;
    }
  }

  if (hits == bloom->hashes) {
    return 1;                // 1 == element already in (or collision)
  }

  return 0;
}

int bloom_init_size(struct bloom * bloom, int32_t entries, double error,
                    int32_t cache_size)
{
  return bloom_init(bloom, entries, error);
}


int bloom_init(struct bloom * bloom, int32_t entries, double error)
{
  bloom->ready = 0;

  if (entries < 1000 || error == 0) {
    return 1;
  }

  bloom->entries = entries;
  bloom->error = error;

  double num = log(bloom->error);
  double denom = 0.480453013918201; // ln(2)^2
  bloom->bpe = -(num / denom);

  double dentries = (double)entries;
  bloom->bits = (int32_t)(dentries * bloom->bpe);

  if (bloom->bits % 8) {
    bloom->bytes = (bloom->bits / 8) + 1;
  } else {
    bloom->bytes = bloom->bits / 8;
  }

  bloom->hashes = (int32_t)ceil(0.693147180559945 * bloom->bpe);  // ln(2)

  bloom->bf = (uint8_t *)calloc(bloom->bytes, sizeof(uint8_t));
  if (bloom->bf == NULL) {
    return 1;
  }

  bloom->ready = 1;
  return 0;
}


int bloom_check(struct bloom * bloom, const void * buffer, int32_t len)
{
  return bloom_check_add(bloom, buffer, len, 0);
}


int bloom_add(struct bloom * bloom, const void * buffer, int32_t len)
{
  return bloom_check_add(bloom, buffer, len, 1);
}


int bloom_merge(struct bloom * bloom, const struct bloom * other)
{
  int32_t i;

  if (bloom->ready != 1 || other->ready != 1) {
    return -1;
  }

  if (bloom->entries != other->entries) {
    return -2;
  }

  if (bloom->error != other->error) {
    return -3;
  }

  for (i = 0; i < bloom->bytes; i++) {
    bloom->bf[i] |= other->bf[i];
  }

  return 0;
}


int bloom_serialize(const struct bloom * bloom, uint8_t ** buffer, int32_t * size)
{
  int32_t offset = 0;

  int32_t entries = htonl(bloom->entries);
  int32_t bytes = htonl(bloom->bytes);

  if (bloom->ready != 1) {
    return -1;
  }

  *size = sizeof(bloom->entries) + sizeof(bloom->error) + sizeof(bloom->bytes) + bloom->bytes;
  *buffer = (uint8_t *) calloc(*size, sizeof(uint8_t));

  memcpy((*buffer) + offset, &entries, sizeof(entries));
  offset += sizeof(entries);

  memcpy((*buffer) + offset, &(bloom->error), sizeof(bloom->error));
  offset += sizeof(bloom->error);

  memcpy((*buffer) + offset, &bytes, sizeof(bytes));
  offset += sizeof(bytes);

  memcpy((*buffer) + offset, bloom->bf, bloom->bytes * sizeof(uint8_t));

  return 0;
}


int bloom_deserialize(struct bloom * bloom, const uint8_t * buffer, int32_t size)
{
  int32_t offset = 0;
  int32_t entries, entries_n;
  double error;
  int32_t bytes, bytes_n;

  if (size < sizeof(entries) + sizeof(error) + sizeof(bytes)) {
    return -2;
  }

  memcpy(&entries_n, buffer + offset, sizeof(entries));
  entries = ntohl(entries_n);
  offset += sizeof(entries);

  memcpy(&error, buffer + offset, sizeof(error));
  offset += sizeof(error);

  memcpy(&bytes_n, buffer + offset, sizeof(bytes));
  bytes = ntohl(bytes_n);
  offset += sizeof(bytes);

  if (size != sizeof(entries) + sizeof(error) + sizeof(bytes) + bytes) {
    return -2;
  }

  bloom_free(bloom);
  bloom_init(bloom, entries, error);

  if (bloom->bytes != bytes) {
    return -2;
  }

  memcpy(bloom->bf, buffer + offset, bytes * sizeof(uint8_t));

  return 0;
}


void bloom_free_serialized_buffer(uint8_t ** buffer)
{
  free(*buffer);
  *buffer = NULL;
}


void bloom_print(struct bloom * bloom)
{
  printf("bloom at %p\n", (void *)bloom);
  printf(" ->entries = %d\n", bloom->entries);
  printf(" ->error = %f\n", bloom->error);
  printf(" ->bits = %d\n", bloom->bits);
  printf(" ->bits per elem = %f\n", bloom->bpe);
  printf(" ->bytes = %d\n", bloom->bytes);
  printf(" ->hash functions = %d\n", bloom->hashes);
}


void bloom_free(struct bloom * bloom)
{
  if (bloom->ready) {
    free(bloom->bf);
  }
  bloom->ready = 0;
}


const char * bloom_version()
{
  return MAKESTRING(BLOOM_VERSION);
}
