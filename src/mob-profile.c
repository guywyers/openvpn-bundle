#include <stdio.h>
#include <string.h>
#include <ctype.h>

#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/pkcs12.h>
#include <openssl/bio.h>
#include <openssl/evp.h>

#include "helpers.h"
#include "config-reader.h"
#include "mob-profile.h"
#include "simple-xml.h"


BIO* GetPKCS12();
bool PayLoadElements(xml_fragment *xml);
bool VPNDetails(xml_fragment *xml);
bool IPV4Dict(xml_fragment *xml);
bool GenericPayLoadKeys(char *payloadType, char* payloadIdentifier, char* payloadUUID, char * payloadDisplayName,
	char *payloadDescription, char * payloadOrganization);
bool CertificatePayload(xml_fragment *xml);
bool VPNPayload();
bool VPNParams(xml_fragment *xml);
bool SSIDList(xml_fragment *xml);
bool ODRules(xml_fragment *xml);
bool HandleInlineTag(configIterator *it, char *tag, bool xmlTypeTag);
bool MakeRule(char *action, char *extraKey, char *extraVal, bool(*valGenerator)(xml_fragment *), xml_fragment *xml);


typedef struct {
	FILE *inFile;
	xml_fragment *xml;
	profile_info *profile;
	char *clientCRT;
	char *clientKey;
	char *rootCA;
} transformContext;

transformContext *context;

bool ToMobileProfile(FILE* from, FILE* to, profile_info * profile)
{
	context = calloc(1, sizeof(transformContext));
	context->inFile = from;
	context->profile = profile;
	context->xml = NewXMLFragment(to);
	assert_or_exit(context->xml, "Failed to open xml document.\n");

	fprintf(to, "<?xml version=\"1.0\" encoding=\"utf-8\" standalone=\"no\"?>\n");
	fprintf(to, "<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList - 1.0.dtd\">\n");
	fprintf(to, "<plist version=\"1.0\">\n");

	bool result = StartTag("dict", context->xml);
	if (result)
	{
		//First do the generic stuff:
		assert_or_exit(GenericPayLoadKeys("Configuration", context->profile->Identifier, NULL, context->profile->Name,
			context->profile->Description, context->profile->Organization), "");

		PushKeyTag("PayloadRemovalDisallowed", context->xml);
		PushBool(false, context->xml);

		result = PushKeyValueArray("PayloadContent", PayLoadElements, context->xml) &&
			CloseTag("dict", context->xml);
	}
	if (result)
	{
		fprintf(to, "</plist>\n");
	}
	CloseXMLDocument(context->xml);
	free(context->clientCRT);
	free(context->clientKey);
	free(context->rootCA);
	free(context);
	return result;
}


inline bool PayLoadElements(xml_fragment *xml)
{
	assert_or_exit(PushKeyValueDict("", VPNPayload, xml), "");
	return PushKeyValueDict("", CertificatePayload, xml);
}

bool VPNPayload(xml_fragment *xml)
{
	char id[strlen(context->profile->Identifier) + 5];
	sprintf(id, "%s.vpn", context->profile->Identifier);

	assert_or_exit(GenericPayLoadKeys("com.apple.vpn.managed", id, NULL, context->profile->VPNOptions->Name,
		context->profile->VPNOptions->Description, context->profile->Organization), "");

	assert_or_exit(PushKeyValueDict("IPv4", IPV4Dict, context->xml), "");

	assert_or_exit(PushKeyValueDict("VPN", VPNDetails, context->xml), "");

	PushKeyValueString("UserDefinedName", context->profile->VPNOptions->Name, xml);
	
	assert_or_exit(PushKeyValueDict("Proxies", NULL, xml), "");

	PushKeyValueString("VPNSubType", "net.openvpn.OpenVPN-Connect.vpnplugin", xml);

	PushKeyValueString("VPNType", "VPN", xml);

	return PushKeyValueDict("VendorConfig", VPNParams, xml);
}

inline bool IPV4Dict(xml_fragment *xml)
{
	PushKeyValueInt("OverridePrimary", 0, xml);
	return true;
}


bool VPNParams(xml_fragment *xml)
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
				assert_or_exit(HandleInlineTag(it, local_tag, true), "");
				free(local_tag);
			}
			else if (IsInlineTag(it->key))
			{
				assert_or_exit(HandleInlineTag(it, it->key, false), "");
			}
			else
			{
				PushKeyValueString(it->key, it->arguments, xml);
			}
		}
	}
	CleanUpConfigIterator(it);
	return true;

}


bool HandleInlineTag(configIterator *it, char *tag, bool xmlTypeTag)
{
	FILE *memFile = NULL;
	char keyDir[2] = "";

	char *buffer = NULL;
	size_t bufLen = 0;

	//It's inline, so we'll buffer it first:
	assert_or_exit((memFile = open_memstream(&(buffer), &bufLen)), "Failed to allocate memory.");
	assert_or_exit((xmlTypeTag ? ExtractInlineTag(it, memFile, false) : ExtractExternalTag(it, memFile, keyDir, false)), "");
	fflush(memFile);

	bool keep_buffer = false;

	if (!strcmp(tag, "key"))
	{
		context->clientKey = buffer;
		keep_buffer = true;
	}
	else if (!strcmp(tag, "cert"))
	{
		context->clientCRT = buffer;
		keep_buffer = true;
	}
	else 
	{
		if (!strcmp(tag, "ca"))
		{
			//Need it for the pkcs12 and the profile BOTH :
			context->rootCA = buffer;
			keep_buffer = true;
		}
		PushMultiLineTag(tag, buffer, bufLen, true, context->xml);
		if (*keyDir)
			PushKeyValueString("key-direction", (isspace(*keyDir) ? "bidirectional" : keyDir), context->xml);

	}
	if (memFile)
	{
		fclose(memFile);
	}
	if (!keep_buffer)
	{
		free(buffer);
	}
	return true;
}


bool VPNDetails(xml_fragment *xml)
{
	PushKeyValueString("AuthenticationMethod", "Certificate", xml);
	PushKeyValueString("PayloadCertificateUUID", context->profile->CertificateUUID, xml);
	PushKeyValueString("RemoteAddress", "DEFAULT", xml);

	if (context->profile->VPNOptions->AllowedSSIDs)
	{
		PushKeyValueInt("OnDemandEnabled", 1, xml);
		return PushKeyValueArray("OnDemandRules", ODRules, xml);
	}
	else
	{
		PushKeyValueInt("OnDemandEnabled", 0, xml);
	}
	return true;

}


bool ODRules(xml_fragment *xml)
{
	//Rule1: action = disconnect, except when SSID matches:
	assert_or_exit(MakeRule("disconnect", "SSIDMatch", NULL, SSIDList, xml),"");

	//Rule2: action = connect when it's a WiFi:
	assert_or_exit(MakeRule("connect", "InterfaceTypeMatch", "WiFi", NULL, xml), "");

	//Rule3 (default): action = disconnect when nothing else matches:
	return MakeRule("disconnect", NULL, NULL, NULL, xml);
}


bool MakeRule(char *action, char *extraKey, char *extraVal, bool(*valGenerator)(xml_fragment *), xml_fragment *xml)
{
	StartTag("dict", xml);
	PushKeyValueString("action", action, xml);
	if (extraKey && extraVal && *extraVal)
	{
		PushKeyValueString(extraKey, extraVal, xml);
	}
	else if (extraKey && valGenerator)
	{
		PushKeyTag(extraKey, xml);
		assert_or_exit(valGenerator(xml), "");
	}
	return CloseTag("dict", xml);
}



bool SSIDList(xml_fragment *xml)
{
	StartTag("array", xml);
	for (char *s = context->profile->VPNOptions->AllowedSSIDs[0]; s; ++s)
		PushString(s, xml);
	return CloseTag("array", xml);
}

bool CertificatePayload(xml_fragment *xml)
{
	char id[strlen(context->profile->Identifier) + 5];
	sprintf(id, "%s.credential", context->profile->Identifier);

	assert_or_exit(context->clientCRT, "Client certificate missing.\n");
	assert_or_exit(context->clientKey, "Client key missing.\n");
	assert_or_exit(context->rootCA, "CA certificate missing.\n");

	assert_or_exit(GenericPayLoadKeys("com.apple.security.pkcs12", id, context->profile->CertificateUUID, context->profile->CertificateName,
		context->profile->CertificateDescription, context->profile->Organization),"");

	PushKeyTag("PayloadContent", context->xml);
	BIO* cert = GetPKCS12();
	assert_or_exit(cert, "");
	char *buffer;
	size_t len = (size_t)(BIO_get_mem_data(cert, &buffer));
	PushMultiLineTag("data", buffer, len, false, xml);
	BIO_free_all(cert);
	return true;
}


BIO* GetPKCS12()
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
		bio = BIO_new(BIO_s_mem());
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
		else
			BIO_flush(bio);
	}

	if (p12) PKCS12_free(p12);

	if (cert) X509_free(cert);

	if (caCert) X509_free(caCert);

	if (cacertstack) sk_X509_free(cacertstack);

	if (pkey) EVP_PKEY_free(pkey);

	return bio;
}


bool GenericPayLoadKeys(char *payloadType, char* payloadIdentifier, char* payloadUUID, char * payloadDisplayName,
	char *payloadDescription, char * payloadOrganization)
{
	PushKeyValueString("PayloadIdentifier", payloadIdentifier, context->xml);
	PushKeyValueString("PayloadType", payloadType, context->xml);
	PushKeyValueInt("PayloadVersion", 1, context->xml);
	PushKeyValueString("PayloadDescription", payloadDescription, context->xml);
	PushKeyValueString("PayloadDisplayName", payloadDisplayName, context->xml);
	PushKeyValueString("PayloadOrganization", payloadOrganization, context->xml);
	PushKeyValueString("PayloadIdentifier", payloadIdentifier, context->xml);

	if (payloadUUID)
		PushKeyValueString("PayloadUUID", payloadUUID, context->xml);
	else
	{
		char * UUID = GetUUIDString();
		PushKeyValueString("PayloadUUID", UUID, context->xml);
		free(UUID);
	}

	return true;
}


