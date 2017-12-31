#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

#include "profile.h"
#include "helpers.h"


profile_info *NewProfileInfo();
bool ParseInput(FILE* infile, profile_info *profile);
void ParseKeyValue(char *input, char *key, char *value, profile_info *profile);

profile_info *ReadProfileFromFile(char *path)
{
	profile_info *result = NewProfileInfo();
	
	if (result != NULL)
	{
		FILE *inFile = fopen(path, "r");
		if (inFile == NULL)
		{
			FreeProfile(result);
			return NULL;
		}
		if (!ParseInput(inFile, result))
		{
			FreeProfile(result);
			result = NULL;
		}
		fclose(inFile);
	}

	return result;
}

bool ParseInput(FILE* infile, profile_info *profile)
{
	char *line = NULL;
	size_t len = 0;
	
	while ((getline(&line, &len, infile)) != -1)
	{
		char *key;
		size_t keyLen;
		char *value;
		size_t valLen;
		if (ParseConfigLine(line, &key, &keyLen, &value, &valLen, NULL, NULL))
		{
			key[keyLen] = 0;
			value[valLen] = 0;
			ParseKeyValue(line, key, value, profile);
		}
	}
	free(line);

	char missing[500] = "";

	if (profile->Name == NULL || profile->Name[0] == 0)
		strcat(missing, "Name");
	if (profile->VPNOptions->Name == NULL || profile->VPNOptions->Name[0] == 0)
		strcat(strcat(missing, *missing != 0 ? " ," : ""), "VPNName");
	if (profile->Identifier == NULL || profile->Identifier[0] == 0)
		strcat(strcat(missing, *missing != 0 ? " ," : ""), "Identifier");
	if (profile->CertificateName == NULL || profile->CertificateName[0] == 0)
		strcat(strcat(missing, *missing != 0 ? " ," : ""), "CertificateName");

	assert_or_exit(*missing == 0, "Missing fields: '%s' in input file.\n", missing);

	return true;
}


void ParseKeyValue(char *input, char *key, char *value, profile_info *profile)
{
	if (!strcmp(key, "ProfileDescription"))
		profile->Description = strdup(value);
	else if (!strcmp(key, "Identifier"))
		profile->Identifier = strdup(value);
	else if (!strcmp(key, "Name"))
		profile->Name = strdup(value);
	else if (!strcmp(key, "Organization"))
		profile->Organization = strdup(value);
	else if (!strcmp(key, "VPNName"))
		profile->VPNOptions->Name = strdup(value);
	else if (!strcmp(key, "CertificateName"))
		profile->CertificateName = strdup(value);
	else if (!strcmp(key, "CertificateDescription"))
		profile->CertificateDescription = strdup(value);
	else if (!strcmp(key, "VPNDescription"))
		profile->VPNOptions->Description = strdup(value);
	else if (!strcmp(key, "Password"))
		profile->Password = strdup(value);
	else if (!strcmp(key, "AllowedSSIDS"))
	{
		char *sids[500];
		char **cur = &sids[0];
		
		for (*cur = strtok(value, ","); *cur; *(++cur) = strtok(NULL, ","));
		profile->VPNOptions->AllowedSSIDs = calloc((size_t)(cur - sids + 1), sizeof(char*));
		memcpy(profile->VPNOptions->AllowedSSIDs, sids, (size_t)(cur - sids + 1) * sizeof(char*));
	}
}


void FreeVPNOptions(VPNInfo *vpn)
{
	if (vpn)
	{
		free(vpn->AllowedSSIDs);
		free(vpn->Description);
		free(vpn->Name);
		free(vpn);
	}
}

void FreeProfile(profile_info *profile)
{
	if (profile)
	{
		FreeVPNOptions(profile->VPNOptions);
		free(profile->CertificateDescription);
		free(profile->CertificateName);
		free(profile->CertificateUUID);
		free(profile->Description);
		free(profile->Identifier);
		free(profile->Name);
		free(profile->Organization);
		free(profile->Password);
		free(profile);
	}
}

profile_info *NewProfileInfo()
{
	profile_info *result = calloc(1, sizeof(profile_info));
	
	result->VPNOptions = calloc(1, sizeof(VPNInfo));

	result->CertificateUUID = GetUUIDString();

	return result;
}


