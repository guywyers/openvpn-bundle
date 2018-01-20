#ifndef CONFIG_READER_H
#define CONFIG_READER_H

#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <stdarg.h>


#include "helpers.h"

typedef struct {
	fileIterator *file;
	char *fullLine;
	char *key;
	char *arguments;
	char *comment;
} configIterator;

extern bool IsInlineTag(char *key);

extern bool MakeProfileBundle(FILE* from, FILE* to);

extern bool ExtractInlineTag(configIterator *it, FILE *dest, bool includeTagLines);

extern bool ExtractExternalTag(configIterator *it, FILE *dest, char *keyDirection, bool includeTagLines);

extern bool NextLine(configIterator *it);

extern configIterator *StartConfigIterator(FILE *file);

extern void CleanUpConfigIterator(configIterator *it);

extern bool IsEOF(configIterator *it);


#endif // !CONFIG_READER_H

