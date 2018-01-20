#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>

#include "config-reader.h"
#include "helpers.h"

const char *tag_keys[] = { "ca", "cert", "dh", "extra-certs", "key", "pkcs12", "secret", "crl-verify", "http-proxy-user-pass", "tls-auth",
"tls-crypt", NULL };

void ExtractValues(configIterator *it);

bool MakeProfileBundle(FILE* from, FILE* to)
{
	configIterator * it = StartConfigIterator(from);

	for (; !IsEOF(it); NextLine(it))
	{
		if (it->key && strpbrk(it->key, "<"))
		{
			assert_or_exit(ExtractInlineTag(it, to, true), "");
		}
		else if (it->key && IsInlineTag(it->key))
		{
			char keyDir[2] = "";
			
			assert_or_exit(ExtractExternalTag(it, to, keyDir, true), "");
			if (*keyDir)
			{
				fprintf(to, "key-direction %s\n", isspace(*keyDir) ? "bidirectional" : keyDir);
			}
		}
		else
			fputs(it->fullLine, to);
	}
	CleanUpConfigIterator(it);
	return true;
}


bool ExtractExternalTag(configIterator *it, FILE *dest, char *keyDirection, bool includeTagLines)
{
	*keyDirection = 0x0;
	char file[strlen(it->arguments) + 1];

	sscanf(it->arguments, "%s %c", file, keyDirection);


	if (!strcmp(it->key, "secret") || !strcmp(it->key, "tls-auth"))
	{
		//Key direction must be empty, 0 or 1
		assert_or_exit(*keyDirection == 0 || *keyDirection == '0' || *keyDirection == '1',
															"Invalid key direction specification: %s\n", keyDirection);
		if (!*keyDirection)
			*keyDirection = ' ';
	}
	else 
		assert_or_exit(!*keyDirection, "Invalid key file specified: '%s'\n", it->arguments);

	FILE *tagFile = fopen(file, "r");
	assert_or_exit(tagFile != NULL, "Invalid key file specified: '%s'\n", file);

	if (includeTagLines)
		fprintf(dest, "<%s>\n", it->key);

	char *line = NULL;
	size_t len = 0;
	while (getline(&line, &len, tagFile) != -1)
	{
		fputs(line, dest);
	}
	if (includeTagLines)
		fprintf(dest, "</%s>\n", it->key);
	fclose(tagFile);
	free(line);

	return true;

}

bool ExtractInlineTag(configIterator *it, FILE *dest, bool includeTagLines)
{
	char *s = strchr(it->fullLine, '<');
	char *e = strchr(it->fullLine, '>');

	assert_or_exit(s && e && e > s, "Incorrectly formatted tag found in input file, line '%s'\n", it->fullLine);

	size_t tagLen = (size_t)(e - s - 1);
	char tag[tagLen + 1];
	strncpy(tag, s + 1, tagLen);
	tag[tagLen] = 0;

	if (includeTagLines)
		fputs(it->fullLine, dest);

	for (NextLine(it); !IsEOF(it); NextLine(it))
	{
		s = strchr(it->fullLine, '<');
		e = strchr(it->fullLine, '>');

		if (!s && !e)
			fputs(it->fullLine, dest);
		else
		{
			//There is a tag on this line, it's either our closing tag or it's a problem:
			assert_or_exit(s && e && !strncmp(tag, s + 2, tagLen) && *(s + 1) == '/',
				"Incorrectly formatted tag found in input file '%s'\n", it->fullLine);

			if (includeTagLines)
				fputs(it->fullLine, dest);

			return true;
		}

	}
	//Have reached end of file without closing tag:
	return FailMessage("Reached end of file before finding closing tag for <%s>\n", tag);
}


bool IsInlineTag(char *key)
{
	if (key[0] == 0)
		return false;

	char **tg = (char **)tag_keys;
	for (; *tg && strcmp(*tg, key); ++tg);

	return (*tg != NULL);
}

configIterator *StartConfigIterator(FILE *file)
{
	configIterator * result = calloc(1,sizeof(configIterator));
	result->file = StartIterator(file);
	
	ExtractValues(result);

	return result;
}

bool NextLine(configIterator *it)
{
	Next(it->file);
	ExtractValues(it);
	return IsEOF(it);
}

void CleanUpConfigIterator(configIterator *it)
{
	free(it->comment);
	free(it->arguments);
	free(it->key);
	CleanUpIterator(it->file);
	free(it);
}

inline bool IsEOF(configIterator *it)
{
	return (it->fullLine == NULL);
}

void ExtractValues(configIterator *it)
{
	free(it->comment);
	free(it->arguments);
	free(it->key);
	it->comment = it->arguments = it->key = NULL;

	it->fullLine = it->file->current;

	if (it->fullLine)
	{
		char *key;
		size_t keyLen;
		char *value;
		size_t valLen;
		char *comment;
		size_t commentLen;

		ParseConfigLine(it->fullLine, &key, &keyLen, &value, &valLen, &comment, &commentLen);
		if (keyLen > 0)
			it->key = strndup(key, keyLen);

		if (valLen > 0)
			it->arguments = strndup(value, valLen);

		if (commentLen > 0)
			it->comment = strndup(comment, commentLen);

	}
}

