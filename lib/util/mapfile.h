#ifndef _MAPFILE_H_
#define _MAPFILE_H_

#include <stddef.h>

/**
 * mapfile(name, fd, len):
 * Open the file ${name} and map it into memory.  Set ${fd} to the file
 * descriptor and ${len} to the file length, and return a pointer to the
 * mapped data.
 */
void * mapfile(const char *, int *, size_t *);

/**
 * unmapfile(ptr, fd, len):
 * Tear down the file mapping created by mapfile.
 */
int unmapfile(void *, int, size_t);

#endif /* !_MAPFILE_H_ */
