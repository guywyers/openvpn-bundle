#ifndef SIMPLE_XML_H
#define SIMPLE_XML_H

#include <stdio.h>

#include <sys/queue.h>

struct xml_level {
	LIST_ENTRY(xml_level) list;
	char *indent;
	char *tag;
} ;


typedef struct 
{
	char *buffer;
	FILE *xml_store;
	LIST_HEAD(, xml_level) levels;
} xml_fragment;

extern xml_fragment* NewXMLFragment(FILE *destination);
extern bool CloseXMLDocument(xml_fragment *doc);
extern bool PushKeyValueDict(char *key, bool(*DictEnumerator)(xml_fragment *), xml_fragment *doc);
extern bool PushKeyValueArray(char *key, bool(*ArrayEnumerator)(xml_fragment *), xml_fragment *doc);
extern void PushKeyValueString(char *key, char *value, xml_fragment *doc);
extern void PushKeyValueInt(char *key, int value, xml_fragment *doc);
extern void PushBool(bool value, xml_fragment *doc);
extern void PushString(char *text, xml_fragment *doc);
extern void PushKeyTag(char *name, xml_fragment *doc);
extern bool PushLineTag(char *tag, char *text, xml_fragment *doc);
extern bool PushMultiLineTag(char *tag, char *buffer, size_t bufLen, bool flattenLines, xml_fragment *doc);
extern bool StartTag(char *tag, xml_fragment *doc);
extern bool CloseTag(char* tag, xml_fragment *doc);
#endif // !SIMPLE_XML.H
