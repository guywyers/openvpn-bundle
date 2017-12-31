#ifndef HELPERS_H
#define HELPERS_H

#include <stdlib.h>
#include <stdbool.h>
#include <stdarg.h>

extern bool ParseConfigLine(char *input, char** key, size_t *keyLen, char** value, size_t *valLen, char **comment, size_t *comLen);

extern FILE *StringReader(char *string);

extern char *GetUUIDString();

typedef struct {
	FILE * file;
	size_t size;
	char * current;
}fileIterator;

extern fileIterator *StartIterator(FILE *file);

extern void CleanUpIterator(fileIterator *it);

extern char *Next(fileIterator *it);

#define assert_or_exit(cond, format, ...) if (!(cond)) {return FailMessage(format, ## __VA_ARGS__);}

extern bool FailMessage(const char *format, ...);
#endif // !HELPERS_H

