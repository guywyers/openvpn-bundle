
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <regex.h>
#include <uuid/uuid.h>

#include "helpers.h"

char *GetUUIDString()
{
	char *result = calloc(37, sizeof(char));

	uuid_t guid;
	uuid_generate(guid);

	uuid_unparse_lower(guid, result);

	return result;
}

bool ParseConfigLine(char *input, char** key, size_t *keyLen, char** value, size_t *valLen, char **comment, size_t *comLen)
{
	regex_t regexp;
	regcomp(&regexp, "[[:space:]]*(([^#;[:space:]:=]+)[[:space:]]*[[:space:]:=][[:space:]]*([^;#]*[^[:space:]#;])?)?([#;].*)?", REG_EXTENDED);
	regmatch_t matchptr[regexp.re_nsub + 1];

	if (key)
	{
		*key = input + strnlen(input, 500) + 1;
		*keyLen = 0;
	}
	if (value)
	{
		*value = input + strnlen(input, 500) + 1;
		*valLen = 0;
	}
	if (comment)
	{
		*comment = input + strnlen(input, 500) + 1;
		*comLen = 0;
	}
	if (regexec(&regexp, input, regexp.re_nsub + 1, matchptr, 0) == 0)
	{
		bool atLeastOne = false;
		if (key && matchptr[2].rm_eo > matchptr[2].rm_so)
		{
			*key = input + matchptr[2].rm_so;
			*keyLen = (size_t)(matchptr[2].rm_eo - matchptr[2].rm_so);
			atLeastOne |= true;
		}
		if (value && matchptr[3].rm_eo > matchptr[3].rm_so)
		{
			*value = input + matchptr[3].rm_so;
			*valLen = (size_t)(matchptr[3].rm_eo - matchptr[3].rm_so);
			atLeastOne |= true;
		}
		if (comment && matchptr[4].rm_eo > matchptr[4].rm_so)
		{
			*comment = input + matchptr[4].rm_so;
			*comLen = (size_t)(matchptr[4].rm_eo - matchptr[4].rm_so);
			atLeastOne |= true;
		}
		return atLeastOne;
	}
	return false;
}

FILE *StringReader(char *string)
{
	FILE *memFile;
	size_t bufLen = strlen(string);
	memFile = fmemopen(string, bufLen, "r");
	if (!memFile)
		fprintf(stderr, "Failed to open memory file.\n");
	return memFile;
}

bool FailMessage(const char *format, ...)
{
	va_list va;

	va_start(va, format);
	vfprintf(stderr, format, va);
	va_end(va);
	return false;
}


fileIterator *StartIterator(FILE *file)
{
	fileIterator *result = calloc(1, sizeof(fileIterator));

	result->file = file;

	Next(result);

	return result;
}

void CleanUpIterator(fileIterator *it)
{
	free(it->current);
	free(it);
}

char *Next(fileIterator *it)
{
	ssize_t state = getline(&(it->current), &(it->size), it->file);
	if (state == -1)
	{
		free(it->current);
		it->current = NULL;
	}
	return it->current;
}

