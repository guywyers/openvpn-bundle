#include "arguments.h"

const char *argp_program_version = "openvpn-bundle v0.2";
const char *argp_program_bug_address = "<guy_wy@hotmail.com>";
static char doc[] = "Creates a unified OpenVPN configuration file by importing external files into inline parameters.";
static struct argp_option options[] = {
	{ "input", 'i', "infile", 0, "Input from file 'infile' instead of standard input." },
	{ "output", 'o', "outfile", 0, "Output to file 'outfile' instead of standard output." },
	{ "mobile-prof", 'm', "profile-input", 0, "Generate iOS mobile configuration profile, using 'profile-input'." },
	{ 0 }
};

static error_t parse_opt(int key, char *arg, struct argp_state *state) {
	arguments *arguments = state->input;
	
	switch (key)
	{
	case 'i':
		arguments->input = arg;
		break;
	case 'o':
		arguments->output = arg;
		break;
	case 'm':
		arguments->mobile_file = arg;
		break;
	case ARGP_KEY_ARG:
		argp_usage(state);
		return ARGP_KEY_ERROR;
	default:
		return 0;
	}
	return 0;
}

static struct argp argp = { options, parse_opt, NULL, doc };

error_t parse_cmd_line(int argc, char **argv, arguments* args)
{
	args->input = NULL;
	args->output = NULL;
	args->mobile_file = NULL;

	return argp_parse(&argp, argc, argv, 0, 0, args);
}
