#include <stdio.h>
#include <string.h>
#include <ctype.h>

#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/pkcs12.h>
#include <openssl/bio.h>
#include <openssl/evp.h>

#include "helpers.h"
# include "config-reader.h"
#include "mob-profile.h"

typedef struct {
	FILE *inFile;
	FILE *outFile;
	profile_info *profile;
	char *clientCRT;
	char *clientKey;
	char *rootCA;
} transformContext;

transformContext *context;

const char indent[] = "   ";

bool GenericPayLoadKeys(char *payloadType, char* payloadIdentifier, char* payloadUUID, char * payloadDisplayName,
	char *payloadDescription, char * payloadOrganization, char *prefix, bool(*ContentGenerator)(char *));
bool GlobalPayLoad(char *prefix);
bool WriteTag(char *tag, bool(*BodyGenerator)(char *), char *prefix);
bool VPNPayload(char *prefix);
bool CertificatePayload(char *prefix);

void DictKeyInt(char *key, int value, char *prefix);
void DictKeyString(char *key, char *value, char *prefix);
void WriteBool(bool value, char *prefix);
void WriteString(char *text, char *prefix);
void WriteKey(char *name, char *prefix); 
bool PayLoadArray(char *prefix);
bool PayLoadElements(char * prefix);
void WriteLineTag(char *tag, char *content, char *prefix);
bool IPV4Dict(char *prefix);
bool VPNDetails(char *prefix);
bool VPNParams(char *prefix);
bool WriteOVPNTag(configIterator *it, char *tag, bool xmlTypeTag, char *prefix);
bool HandleInlineTag(configIterator *it, char *tag, bool xmlTypeTag, char *prefix);
bool ExtractTag(configIterator *it, FILE *dest, bool xmlTypeTag, bool keepLines, char *keyDir);
bool ODRules(char *prefix);
bool Rule1(char *prefix);
bool Rule2(char *prefix);
bool Rule3(char *prefix);
bool SSIDList(char * prefix);
bool ExtractCertificate(char *prefix);
bool MakePKCS12(char *prefix);



bool ToMobileProfile(FILE* from, FILE* to, profile_info * profile)
{
	context = calloc(1, sizeof(transformContext));
	context->inFile = from;
	context->outFile = to;
	context->profile = profile;

	fprintf(context->outFile, "<?xml version=\"1.0\" encoding=\"utf-8\" standalone=\"no\"?>\n");
	fprintf(context->outFile, "<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList - 1.0.dtd\">\n");
	fprintf(context->outFile, "<plist version=\"1.0\">\n");

	bool result = WriteTag("dict", GlobalPayLoad, (char*)indent);
	if (result)
	{
		fprintf(context->outFile, "</plist>\n");
	}
	free(context->clientCRT);
	free(context->clientKey);
	free(context->rootCA);
	free(context);
	return result;
}


bool GlobalPayLoad(char *prefix)
{
	//First do the generic stuff:
	assert_or_exit(GenericPayLoadKeys("Configuration", context->profile->Identifier, NULL, context->profile->Name,
		context->profile->Description, context->profile->Organization, prefix, PayLoadArray), "");

	WriteKey("PayloadRemovalDisallowed", prefix);

	WriteBool(false, prefix);

	return true;
}

inline bool PayLoadArray(char *prefix)
{
	return WriteTag("array", PayLoadElements, prefix);
}

inline bool PayLoadElements(char * prefix)
{
	assert_or_exit(WriteTag("dict", VPNPayload, prefix), "");
	return WriteTag("dict", CertificatePayload, prefix);
}

bool VPNPayload(char *prefix)
{
	char id[strlen(context->profile->Identifier) + 5];
	sprintf(id, "%s.vpn", context->profile->Identifier);

	assert_or_exit(GenericPayLoadKeys("com.apple.vpn.managed", id, NULL, context->profile->VPNOptions->Name,
		context->profile->VPNOptions->Description, context->profile->Organization, prefix, NULL), "");
	WriteKey("IPv4", prefix);
	assert_or_exit(WriteTag("dict", IPV4Dict, prefix), "");

	WriteKey("VPN", prefix);
	assert_or_exit(WriteTag("dict", VPNDetails, prefix), "");
	WriteKey("VendorConfig", prefix);
	assert_or_exit(WriteTag("dict", VPNParams, prefix), "");
	DictKeyString("UserDefinedName", context->profile->VPNOptions->Name, prefix);
	WriteKey("Proxies", prefix);
	WriteTag("dict", NULL, prefix);
	DictKeyString("VPNSubType", "net.openvpn.OpenVPN-Connect.vpnplugin", prefix);
	DictKeyString("VPNType", "VPN", prefix);

	return true;
}

inline bool IPV4Dict(char *prefix)
{
	DictKeyInt("OverridePrimary", 0, prefix);
	return true;
}

bool VPNParams(char *prefix)
{
	configIterator * it = StartConfigIterator(context->inFile);

	for (; !IsEOF(it); NextLine(it))
	{
		if (it->key && strlen(it->key) > 0)
		{
			char* t_st = strpbrk(it->key, "<");
			if (t_st)
			{
				++t_st;
				char *local_tag = strndup(t_st, strcspn(t_st, ">"));
				assert_or_exit(HandleInlineTag(it, local_tag, true, prefix), "");
				free(local_tag);
			}
			else if (IsInlineTag(it->key))
			{
				assert_or_exit(HandleInlineTag(it, it->key, false, prefix), "");
			}
			else
			{
				DictKeyString(it->key, it->arguments, prefix);
			}
		}
	}
	CleanUpConfigIterator(it);
	return true;

}

bool HandleInlineTag(configIterator *it, char *tag, bool xmlTypeTag, char *prefix)
{
	size_t bufLen = 0;
	FILE *memFile = NULL;
	char keyDir[2] = "";

	if (!strcmp(tag, "key"))
	{
		assert_or_exit((memFile = open_memstream(&(context->clientKey), &bufLen)), "Failed to allocate memory.");
		assert_or_exit(ExtractTag(it, memFile, xmlTypeTag, true, keyDir), "");
	}
	else if (!strcmp(tag, "cert"))
	{
		assert_or_exit((memFile = open_memstream(&(context->clientCRT), &bufLen)), "Failed to allocate memory.");
		assert_or_exit(ExtractTag(it, memFile, xmlTypeTag, true, keyDir), "");
	}
	else if (!strcmp(tag, "ca"))
	{
		//Need it for the pkcs12 and the profile BOTH :
		assert_or_exit((memFile = open_memstream(&(context->rootCA), &bufLen)), "Failed to allocate memory.");
		assert_or_exit(ExtractTag(it, memFile, xmlTypeTag, true, keyDir), "");
		fflush(memFile);
		fprintf(context->outFile, "%s<%s>", prefix, tag);
		FILE *bufReader = fmemopen(context->rootCA, bufLen, "r");
		char *line = NULL;
		size_t lineLen = 0;
		while (getline(&line, &lineLen, bufReader) != -1)
		{
			fprintf(context->outFile, "%.*s\\n", (int)strcspn(line, "\r\n"), line);
		}
		fprintf(context->outFile, "</%s>\n", tag);
		free(line);
		fclose(bufReader);
	}
	if (memFile)
	{
		fclose(memFile);
		return true;
	}
	else
		return WriteOVPNTag(it, tag, xmlTypeTag, prefix);
}

bool WriteOVPNTag(configIterator *it, char *tag, bool xmlTypeTag, char *prefix)
{
	char keyDir[2] = "";

	fprintf(context->outFile, "%s<%s>", prefix, tag);
	assert_or_exit(ExtractTag(it, context->outFile, xmlTypeTag, false, keyDir), "");
	fprintf(context->outFile, "%s</%s>\n", prefix, tag);
	if (*keyDir)
		DictKeyString("key-direction", (isspace(*keyDir) ? "bidirectional" : keyDir), prefix);	
	return true;
}

inline bool ExtractTag(configIterator *it, FILE *dest, bool xmlTypeTag, bool keepLines, char *keyDir)
{
	if (xmlTypeTag)
	{
		return ExtractInlineTag(it, dest, false, !keepLines);
	}
	else
	{
		return ExtractExternalTag(it, dest, keyDir, false, !keepLines);
	}
}

bool VPNDetails(char *prefix)
{
	DictKeyString("AuthenticationMethod", "Certificate", prefix);
	DictKeyString("PayloadCertificateUUID", context->profile->CertificateUUID, prefix);
	DictKeyString("RemoteAddress", "DEFAULT", prefix);

	if (context->profile->VPNOptions->AllowedSSIDs)
	{
		DictKeyInt("OnDemandEnabled", 1, prefix);
		WriteKey("OnDemandRules", prefix);
		return WriteTag("array", ODRules, prefix);
	}
	else
	{
		DictKeyInt("OnDemandEnabled", 0, prefix);
	}
	return true;

}

bool ODRules(char *prefix)
{
	assert_or_exit(WriteTag("dict", Rule1, prefix), "");
	assert_or_exit(WriteTag("dict", Rule2, prefix), "");
	return WriteTag("dict", Rule3, prefix);
}

bool Rule1(char *prefix)
{
	DictKeyString("Action", "Disconnect", prefix);
	WriteKey("SSIDMatch", prefix);
	return WriteTag("array", SSIDList, prefix);
}

bool Rule2(char *prefix)
{
	DictKeyString("Action", "Connect", prefix);
	DictKeyString("InterfaceTypeMatch", "WiFi", prefix);
	return true;
}

bool Rule3(char *prefix)
{
	DictKeyString("Action", "Disconnect", prefix);
	return true;
}

bool SSIDList(char * prefix)
{
	for (char *s = context->profile->VPNOptions->AllowedSSIDs[0]; s; ++s)
		WriteString(s, prefix);
	return true;
}


bool CertificatePayload(char *prefix)
{
	char id[strlen(context->profile->Identifier) + 5];
	sprintf(id, "%s.credential", context->profile->Identifier);

	assert_or_exit(context->clientCRT, "Client certificate missing.\n");
	assert_or_exit(context->clientKey, "Client key missing.\n");
	assert_or_exit(context->rootCA, "CA certificate missing.\n");

	return GenericPayLoadKeys("com.apple.security.pkcs12", id, context->profile->CertificateUUID, context->profile->CertificateName,
		context->profile->CertificateDescription, context->profile->Organization, prefix, ExtractCertificate);
}

inline bool ExtractCertificate(char *prefix)
{
	return WriteTag("data", MakePKCS12, prefix);
}

bool MakePKCS12(char * prefix)
{
	EVP_PKEY *pkey = NULL;
	X509 *cert = NULL;
	X509 *caCert = NULL;
	PKCS12 *p12 = NULL;
	STACK_OF(X509) *cacertstack = NULL;
	BIO *bio, *b64;

	OpenSSL_add_all_algorithms();
	ERR_load_crypto_strings();

	FILE *memFile;
	bool result;
	result = ((memFile = StringReader(context->rootCA)) != NULL);

	if (result)
	{
		result = ((caCert = PEM_read_X509(memFile, NULL, NULL, NULL)) != NULL);
		if (!result)
			fprintf(stderr, "Failed to read in CA Certificate.\n");
		fclose(memFile);
	}

	result &= ((memFile = StringReader(context->clientCRT)) != NULL);
	if (result)
	{
		result = ((cert = PEM_read_X509(memFile, NULL, NULL, NULL)) != NULL);
		if (!result)
			fprintf(stderr, "Failed to read in Client Certificate.\n");
		fclose(memFile);
	}

	result &= ((memFile = StringReader(context->clientKey)) != NULL);
	if (result)
	{
		result = ((pkey = PEM_read_PrivateKey(memFile, NULL, NULL, NULL)) != NULL);
		if (!result)
			fprintf(stderr, "Failed to read in Private Key.\n");
		fclose(memFile);
	}

	if (result)
	{
		result = ((cacertstack = sk_X509_new_null()) != NULL);
		if (!result)
			fprintf(stderr, "Error creating STACK_OF(X509) structure.\n");
		sk_X509_push(cacertstack, caCert);
	}

	if (result)
	{
		p12 = PKCS12_create(context->profile->Password ? context->profile->Password : "", context->profile->CertificateName,
			pkey, cert, cacertstack, 0, 0, 0, 0, 0);
		result = (p12 != NULL);
		if (!result)
			fprintf(stderr, "Error generating a valid PKCS12 certificate.\n");
	}

	if (result)
	{
		b64 = BIO_new(BIO_f_base64());
		bio = BIO_new_fp(context->outFile, BIO_NOCLOSE);
		result = (b64 && bio);
		if (!result)
			fprintf(stderr, "Error creating convertors.\n");
		else
			bio = BIO_push(b64, bio);
	}

	if (result)
	{
		result = (i2d_PKCS12_bio(bio, p12) > 0);
		if (!result)
			fprintf(stderr, "Error exporting the PKCS12 certificate.\n");
	}

	if (bio)
	{
		BIO_flush(bio);
		BIO_free_all(bio);
	}
	if (p12) PKCS12_free(p12);

	if (cert) X509_free(cert);

	if (caCert) X509_free(caCert);

	if (cacertstack) sk_X509_free(cacertstack);

	if (pkey) EVP_PKEY_free(pkey);

	return result;
}

bool GenericPayLoadKeys(char *payloadType, char* payloadIdentifier, char* payloadUUID, char * payloadDisplayName,
	char *payloadDescription, char * payloadOrganization, char *prefix, bool(*ContentGenerator)(char *))
{
	DictKeyString("PayloadIdentifier", payloadIdentifier, prefix);
	DictKeyString("PayloadType", payloadType, prefix);
	DictKeyInt("PayloadVersion", 1, prefix);
	DictKeyString("PayloadDescription", payloadDescription, prefix);
	DictKeyString("PayloadDisplayName", payloadDisplayName, prefix);
	DictKeyString("PayloadOrganization", payloadOrganization, prefix);
	DictKeyString("PayloadIdentifier", payloadIdentifier, prefix);

	if (payloadUUID)
		DictKeyString("PayloadUUID", payloadUUID, prefix);
	else
	{
		char * UUID = GetUUIDString();
		DictKeyString("PayloadUUID", UUID, prefix);
		free(UUID);
	}

	if (ContentGenerator)
	{
		WriteKey("PayloadContent", prefix);
		assert_or_exit((*ContentGenerator)(prefix),"");
	}
	return true;
}

inline void DictKeyInt(char *key, int value, char *prefix)
{
	WriteKey(key, prefix);
	fprintf(context->outFile, "%s<integer>%d</integer>\n", prefix, value);
}

inline void DictKeyString(char *key, char *value, char *prefix)
{
	if (value)
	{
		WriteKey(key, prefix);
		WriteString(value, prefix);
	}
}

inline void WriteBool(bool value, char *prefix)
{
	fprintf(context->outFile, "%s<%s/>\n", prefix, value ? "true" : "false");
}


inline void WriteString(char *text, char *prefix)
{
	WriteLineTag("string", text, prefix);
}

inline void WriteKey(char *name, char *prefix)
{
	WriteLineTag("key", name, prefix);
}

inline void WriteLineTag(char *tag, char *content, char *prefix)
{
	fprintf(context->outFile, "%s<%s>%s</%s>\n", prefix, tag, content, tag);
}

bool WriteTag(char *tag, bool(*BodyGenerator)(char *), char *prefix)
{ 
	if (BodyGenerator)
	{
		fprintf(context->outFile, "%s<%s>\n", prefix, tag);
		char ext_pref[strlen(prefix) + strlen(indent) + 1];
		sprintf(ext_pref, "%s%s", prefix, indent);
		assert_or_exit((*BodyGenerator)(ext_pref), "");
		fprintf(context->outFile, "%s</%s>\n", prefix, tag);
	}
	else
		fprintf(context->outFile, "%s<%s/>\n", prefix, tag);

	return true;
}

