#pragma once

typedef struct 
{
	char *Name;
	char *Description;
	char **AllowedSSIDs;
}VPNInfo;

typedef struct 
{
	char *Password;
	char *Description;
	char *Identifier;
	char *Name;
	char *Organization;
	char *CertificateUUID;
	char *CertificateName;
	char *CertificateDescription;
	VPNInfo *VPNOptions;
} profile_info;


extern profile_info *ReadProfileFromFile(char *path);

extern void FreeProfile(profile_info *profile);