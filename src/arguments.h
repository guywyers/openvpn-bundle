#ifndef ARGUMENTS_H
#define ARGUMENTS_H
#include <argp.h>
#include <stdbool.h>


typedef struct {
	char *input;
	char *output;
	char *mobile_file;
} arguments;

extern error_t parse_cmd_line(int argc, char **argv, arguments* args);
#endif // ARGUMENTS_H
