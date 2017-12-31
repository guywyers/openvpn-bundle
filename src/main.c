#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>

#include "arguments.h"

#include "profile.h"
#include "config-reader.h"
#include "mob-profile.h"

static arguments args;
static FILE *inFile = NULL;
static FILE *outFile = NULL;
static FILE *memFile = NULL;

static char *outputBuffer;
static size_t bufferLength;

static FILE *InputFile();
static FILE *OutputFile();
static FILE *MemoryFile();

bool GetPassword(profile_info *profile);
static void CleanUp(profile_info *profile, int exitCode);


int main(int argc, char **argv)
{
	if (parse_cmd_line(argc, argv, &args) != 0)
		exit(1);

	profile_info *profile = NULL;
	if (args.mobile_file != NULL)
	{
		if ((profile = ReadProfileFromFile(args.mobile_file)) == NULL)
			exit(2);
		//No password in input params, if we can use stdin and stdout,
		//we'll ask for it. Otherwise it's too bad...
		if (!profile->Password)
		{
			if (!args.input || !args.output || !isatty(STDIN_FILENO) || !isatty(STDOUT_FILENO))
			{
				fprintf(stderr, "No profile password in input and not possible to ask user for it\n.");
				exit(3);
			}
			else if (!GetPassword(profile))
				exit(3);
		}
	}

	if (!InputFile() || !MemoryFile())
		CleanUp(profile, 4);

	if (args.mobile_file != NULL)
	{
		if (!ToMobileProfile(InputFile(), MemoryFile(), profile))
			CleanUp(profile, 5);
	}
	else
	{
		if (!MakeProfileBundle(InputFile(), MemoryFile()))
			CleanUp(profile, 6);
	}

	if (!OutputFile())
		CleanUp(profile,7);

	fflush(MemoryFile());
	fwrite(outputBuffer, bufferLength, 1, OutputFile());

	CleanUp(profile, 0);
}


static FILE *InputFile()
{
	if (!inFile)
	{
		if (args.input)
		{
			if (!(inFile = fopen(args.input, "r")))
				fprintf(stderr, "Error opening input file '%s'\n", args.input);
		}
		else
			inFile = stdin;
	}
	return inFile;
}

static FILE *OutputFile()
{
	if (!outFile)
	{
		if (args.output)
		{
			if (!(outFile = fopen(args.output, "w")))
				fprintf(stderr, "Error opening output file '%s'\n", args.output);
		}
		else
			outFile = stdout;
	}
	return outFile;
}

static FILE *MemoryFile()
{
	if (!memFile)
	{
		outputBuffer = NULL;
		if (!(memFile = open_memstream(&outputBuffer, &bufferLength)))
			fprintf(stderr, "Error allocating output buffer.\n");
	}
	return memFile;
}

static void CleanUp(profile_info *profile, int exitCode)
{
	if (inFile)
		fclose(inFile);

	if (outFile)
		fclose(outFile);

	if (memFile)
		fclose(memFile);

	free(outputBuffer);

	FreeProfile(profile);

	exit(exitCode);
}

bool GetPassword(profile_info *profile)
{
	for (int i = 0; i < 2; ++i)
	{
		profile->Password = strdup(getpass("Enter password to protect certificate: "));
		if (!strcmp(profile->Password, getpass("Retype password to confirm: ")))
			break;
		profile->Password = NULL;
	}

	if (!profile->Password)
	{
		printf("Invalid password entry.\n");
		return false;
	}
	return true;
}