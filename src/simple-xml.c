#include <stdlib.h>
#include <stdbool.h>
#include <string.h>

#include "simple-xml.h"
#include "helpers.h"


const char tab[] = "   ";

void FreeLevel(struct xml_level *lev);

#define current_indent(doc) (doc->levels.lh_first ? doc->levels.lh_first->indent : tab)

xml_fragment* NewXMLFragment(FILE *destination)
{
	xml_fragment *result = calloc(1, sizeof(xml_fragment));

	if (result)
	{
		result->xml_store = destination;
		LIST_INIT(&(result->levels));		
	}

	return result;
}

bool CloseXMLDocument(xml_fragment *doc)
{
	int len = 0;
	struct xml_level *l;
	while ((l = doc->levels.lh_first))
	{
		LIST_REMOVE(doc->levels.lh_first, list);
		FreeLevel(l);
		++len;
	}
	free(doc);
	return (len == 0);
}

bool PushKeyValueDict(char *key, bool(*DictEnumerator)(xml_fragment *), xml_fragment *doc)
{
	if (key && *key)
		PushKeyTag(key, doc);

	StartTag("dict", doc);
	if (DictEnumerator)
		assert_or_exit(DictEnumerator(doc), "");
	return CloseTag("dict", doc);
}

bool PushKeyValueArray(char *key, bool(*ArrayEnumerator)(xml_fragment *), xml_fragment *doc)
{
	PushKeyTag(key, doc);
	StartTag("array", doc);
	if (ArrayEnumerator)
		assert_or_exit(ArrayEnumerator(doc), "");
	CloseTag("array", doc);
	return true;
}

inline void PushKeyValueString(char *key, char *value, xml_fragment *doc)
{
	if (value)
	{
		PushKeyTag(key, doc);
		PushString(value, doc);
	}
}

inline void PushKeyValueInt(char *key, int value, xml_fragment *doc)
{
	PushKeyTag(key, doc);
	fprintf(doc->xml_store, "%s<integer>%d</integer>\n", current_indent(doc), value);
}

inline void PushBool(bool value, xml_fragment *doc)
{
	fprintf(doc->xml_store, "%s<%s/>\n", current_indent(doc), value ? "true" : "false");
}

inline void PushString(char *text, xml_fragment *doc)
{
	PushLineTag("string", text, doc);
}

inline void PushKeyTag(char *name, xml_fragment *doc)
{
	PushLineTag("key", name, doc);
}

bool PushLineTag(char *tag, char *text, xml_fragment *doc)
{
	fprintf(doc->xml_store, "%s<%s>%s</%s>\n", current_indent(doc), tag, text, tag);
	return true;
}

bool PushMultiLineTag(char *tag, char *buffer, size_t bufLen, bool flattenLines, xml_fragment *doc)
{
	FILE *bufReader = fmemopen(buffer, bufLen, "r");
	assert_or_exit(bufReader, "Failed to open memory buffer.\n");
	char *line = NULL;
	size_t lineLen = 0;
	if (flattenLines)
	{
		fprintf(doc->xml_store, "%s<%s>", current_indent(doc), tag);
		while (getline(&line, &lineLen, bufReader) != -1)
		{
			fprintf(doc->xml_store, "%.*s\\n", (int)strcspn(line, "\r\n"), line);
		}
	}
	else
	{
		fprintf(doc->xml_store, "%s<%s>\n", current_indent(doc), tag);
		while (getline(&line, &lineLen, bufReader) != -1)
		{
			fprintf(doc->xml_store, "%s%s", current_indent(doc), line);
		}
	}
	fclose(bufReader);

	fprintf(doc->xml_store, "%s</%s>\n", current_indent(doc), tag);
	return true;
}

bool StartTag(char *tag, xml_fragment *doc)
{
	char ind_buffer[500];
	struct xml_level *new_tag = malloc(sizeof(struct xml_level));
	if (new_tag)
	{
		fprintf(doc->xml_store, "%s<%s>\n", current_indent(doc), tag);
		sprintf(ind_buffer, "%.400s%s", current_indent(doc), tab);
		new_tag->indent = strdup(ind_buffer);
		new_tag->tag = strdup(tag);
		LIST_INSERT_HEAD(&doc->levels, new_tag, list);
	}
	return (new_tag != NULL);
}


bool CloseTag(char* tag, xml_fragment *doc)
{
	struct xml_level *curTag = doc->levels.lh_first;
	assert_or_exit(!strcmp(tag, curTag->tag), "Mismatch in tags: open tag = <%s>, attempting to close <%s>\n", curTag->tag, tag);
	LIST_REMOVE(curTag, list);

	fprintf(doc->xml_store, "%s</%s>\n", current_indent(doc), curTag->tag);
	return true;
}


void FreeLevel(struct xml_level *lv)
{
	free(lv->indent);
	free(lv->tag);
	free(lv);
}