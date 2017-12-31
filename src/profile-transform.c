#include <stdbool.h>
#include <string.h>
#include <stdlib.h>

#include "profile-transform.h"
#include "helpers.h"
#include "config-reader.h"

bool ExtractTag(fileIterator *it, FILE *dest);
bool ProcessInlineTag(char *key, char *arguments, FILE *dest);

//const char *tag_keys[] = { "ca", "cert", "dh", "extra-certs", "key", "pkcs12", "secret", "crl-verify", "http-proxy-user-pass", "tls-auth", 
//							"tls-crypt", NULL };

bool TransformProfile(FILE* from, FILE* to)
{
	configIterator * it = StartConfigIterator(from);

	for (; !IsEOF(it); NextLine(it))
	{
		if (it->key && strpbrk(it->key, "<"))
		{
			//assert_or_exit(ExtractTag(it->file, to), "");
			assert_or_exit(ExtractInlineTag(it, to, true, false), "");
		}
		else if (it->key && IsInlineTag(it->key))
		{
			//assert_or_exit(ProcessInlineTag(it->key, it->arguments, to), "");
			assert_or_exit(ExtractExternalTag(it, to, true, false), "");
		}
		else
			fputs(it->fullLine, to);
	}
	CleanUpConfigIterator(it);
	return true;
}


bool ProcessInlineTag(char *key, char *arguments, FILE *dest)
{
	char d[51] = { 0x0 };
	char file[strlen(arguments) + 1];

	sscanf(arguments, "%s %50s", file, d);

	//Key direction must be empty, 0 or 1
	assert_or_exit(d[0] == 0 || !strcmp(d, "0") || !strcmp(d, "1"), "Invalid key direction specification: %s\n", d)

	if (!strcmp(key, "secret") || !strcmp(key, "tls-auth"))
	{
		fprintf(dest, "key-direction %s\n", d[0] ?  d : "bidirectional");
	}
	else
		assert_or_exit(d[0] == 0, "Invalid key file specified: '%s'\n", arguments);

	FILE *tagFile = fopen(file, "r");
	assert_or_exit(tagFile != NULL, "Invalid key file specified: '%s'\n", arguments);
	

	fprintf(dest, "<%s>\n", key);
	char *line = NULL;
	size_t len = 0;
	while (getline(&line, &len, tagFile) != -1)
	{
		fputs(line, dest);
	}
	fprintf(dest, "</%s>\n", key);
	fclose(tagFile);
	free(line);

	return true;
}



bool ExtractTag(fileIterator *it, FILE *dest)
{
	char *s = strchr(it->current, '<');
	char *e = strchr(it->current, '>');

	assert_or_exit(s && e && e > s, "Incorrectly formatted tag found in input file, line '%s'\n",it->current);

	size_t tagLen = (size_t)(e - s - 1);
	char tag[tagLen + 1];
	strncpy(tag, s + 1, tagLen);
	tag[tagLen] = 0;

	fputs(it->current,dest);

	while (Next(it))
	{
		s = strchr(it->current, '<');
		e = strchr(it->current, '>');

		if (!s && !e)
			fputs(it->current, dest);
		else
		{
			//There is a tag on this line, it's either our closing tag or it's a problem:
			assert_or_exit(s && e && !strncmp(tag, s + 2,tagLen) && *(s + 1) == '/',
				"Incorrectly formatted tag found in input file '%s'\n", it->current);
			fputs(it->current, dest);
			return true;
		}
			
	}
	//Have reached end of file without closing tag:
	return FailMessage("Reached end of file before finding closing tag for <%s>\n", tag);
}



