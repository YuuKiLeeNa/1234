#include "pch.h"
#include"RsaRelate.h"
#include "openssl/rsa.h"
#include "openssl/pem.h"
#include<algorithm>
#include<assert.h>
#include<fstream>
#include<string.h>
#include<memory>
#include<functional>

#define RSA_HEAD 11

RsaRelate::RsaRelate(const std::string &pubKey, const std::string &priKey):m_pubkey(pubKey)
,m_prikey(priKey)
, m_rsa_pub(nullptr)
, m_rsa_pri(nullptr)
{
	if (!pubKey.empty()) 
	{
		BIO *keybio = BIO_new_mem_buf((unsigned char *)m_pubkey.c_str(), -1);
		//m_rsa_pub = PEM_read_bio_RSA_PUBKEY(keybio, &m_rsa_pub, NULL, NULL);
		m_rsa_pub = PEM_read_bio_RSAPublicKey(keybio, &m_rsa_pub, NULL, NULL);
		BIO_free(keybio);
	}
	if (!priKey.empty())
	{
		BIO *keybio = BIO_new_mem_buf((unsigned char *)m_prikey.c_str(), -1);
		m_rsa_pri = PEM_read_bio_RSAPrivateKey(keybio, &m_rsa_pri, NULL, NULL);
		BIO_free(keybio);
	}
}

RsaRelate::~RsaRelate()
{
	if(m_rsa_pub)
		RSA_free(m_rsa_pub);
	if(m_rsa_pri)
		RSA_free(m_rsa_pri);
}

std::string RsaRelate::pub_block_encrypt(const std::string &clearText)
{
	if (m_pubkey.empty() || clearText.empty())
		return "";
	
	auto strsets = getBlockToEncryptVector(clearText);
	auto keysize = RSA_size(m_rsa_pub);

	std::string result;
	result.reserve(strsets.size() * keysize);

	std::for_each(std::make_move_iterator(strsets.begin()), std::make_move_iterator(strsets.end()), [this,&result](decltype(strsets)::value_type &&str)
		{
			result += pub_encrypt(std::move(str));
		});

	return result;
}

std::string RsaRelate::pri_stream_decrypt(const std::string & cipherText)
{
	if (m_prikey.empty() || cipherText.empty())
		return "";

	std::string tmpString = m_prikey_deLeftString + cipherText;
	int keysize = RSA_size(m_rsa_pri);

	int cipherTextSize = tmpString.size();
	int leftSize = cipherTextSize % keysize;
	m_prikey_deLeftString = tmpString.substr(cipherTextSize - leftSize);
	tmpString.resize(cipherTextSize - leftSize);

	auto strsets = getBlockToDecryptVector(tmpString);

	std::string result;
	result.reserve(keysize*strsets.size());
	std::for_each(std::make_move_iterator(strsets.begin()), std::make_move_iterator(strsets.end()), [this, &result](decltype(strsets)::value_type&&str)
		{
			result += pri_decrypt(std::move(str));
		});
	return result;
}

std::string RsaRelate::pub_stream_decrypt(const std::string & cipherText)
{
	if (m_pubkey.empty() || cipherText.empty())
		return "";

	std::string tmpString = m_pubkey_deLeftString + cipherText;
	int tmpStringLen = tmpString.size();
	int keysize = RSA_size(m_rsa_pub);
	int leftSize = tmpStringLen % keysize;
	m_pubkey_deLeftString = tmpString.substr(tmpStringLen - leftSize);
	tmpString.resize(tmpStringLen - leftSize);

	auto strsets = getBlockToDecryptVector(tmpString);
	std::string result;
	result.reserve(keysize*strsets.size());
	std::for_each(std::make_move_iterator(strsets.begin()), std::make_move_iterator(strsets.end()), [this, &result](decltype(strsets)::value_type&&str)
		{
			result += pub_decrypt(std::move(str));
		});
	return result;
}

std::string RsaRelate::pri_block_encrypt(const std::string & clearText)
{
	if (m_prikey.empty() || clearText.empty())
		return "";

	auto strsets = getBlockToEncryptVector(clearText);
	auto keysize = RSA_size(m_rsa_pri);

	std::string result;
	result.reserve(strsets.size() * keysize);

	std::for_each(std::make_move_iterator(strsets.begin()), std::make_move_iterator(strsets.end()), [this, &result](decltype(strsets)::value_type &&str)
		{
			result += pri_encrypt(std::move(str));
		});

	return result;
}

void RsaRelate::generateRSAKey(std::string strKey[2], int bits, const std::string&pubPath, const std::string&priPath)
{  
	size_t pri_len;
	size_t pub_len;
	char *pri_key = NULL;
	char *pub_key = NULL;

	srand(time(nullptr));

	RSA *keypair = RSA_new();
	std::unique_ptr<RSA, void(*)(RSA*)> keypairfree(keypair, RSA_free);

	int ret = 0;
	BIGNUM* bne = BN_new();
	std::unique_ptr<BIGNUM, void(*)(BIGNUM*)>bnefree(bne, BN_free);

	ret = BN_set_word(bne, RSA_F4);
	ret = RSA_generate_key_ex(keypair, bits, bne, NULL);


	//RSA_generate_key_ex()
	BIO *pri = BIO_new(BIO_s_mem());
	std::unique_ptr<BIO, void(*)(BIO*)>prifree(pri, BIO_free_all);

	BIO *pub = BIO_new(BIO_s_mem());
	std::unique_ptr<BIO, void(*)(BIO*)>pubfree(pub, BIO_free_all);

	PEM_write_bio_RSAPrivateKey(pri, keypair, NULL, NULL, 0, NULL, NULL);
	PEM_write_bio_RSAPublicKey(pub, keypair);

	pri_len = BIO_pending(pri);
	pub_len = BIO_pending(pub);

	pri_key = (char *)malloc(pri_len + 1);
	std::unique_ptr<char[], std::function<void(char*)>>prikeyfree(pri_key, [](char*c) {free(c); });
	pub_key = (char *)malloc(pub_len + 1);
	std::unique_ptr<char[], std::function<void(char*)>>pubkeyfree(pub_key, [](char*c) {free(c); });

	BIO_read(pri, pri_key, pri_len);
	BIO_read(pub, pub_key, pub_len);

	pri_key[pri_len] = '\0';
	pub_key[pub_len] = '\0';

	strKey[0] = pub_key;
	strKey[1] = pri_key;

    std::ofstream pubKeyStream(pubPath);
    if (!pubKeyStream)
	{
		assert(false);
		return;
	}
    pubKeyStream<<pub_key;
	pubKeyStream.flush();
    std::ofstream priKeyStream(priPath);
    if (!priKeyStream)
	{
		assert(false);
		return;
	}
    priKeyStream<<pri_key;
	priKeyStream.flush();
}

std::string RsaRelate::pub_block_decrypt(const std::string & cipherText)
{
	if (m_pubkey.empty() || cipherText.empty())
		return "";

	auto strsets = getBlockToDecryptVector(cipherText);
	auto keysize = RSA_size(m_rsa_pub);
	std::string result;
	result.reserve(keysize*strsets.size());
	std::for_each(std::make_move_iterator(strsets.begin()), std::make_move_iterator(strsets.end()), [this, &result](decltype(strsets)::value_type&&str)
		{
			result += pub_decrypt(std::move(str));
		});
	return result;
}

std::string RsaRelate::pri_block_decrypt(const std::string & cipherText)
{
	if (m_prikey.empty() || cipherText.empty())
		return "";

	auto strsets = getBlockToDecryptVector(cipherText);

	std::string result;
	int keysize = RSA_size(m_rsa_pri);
	result.reserve(keysize*strsets.size());
	std::for_each(std::make_move_iterator(strsets.begin()), std::make_move_iterator(strsets.end()), [this, &result](decltype(strsets)::value_type &&str)
		{
			result += pri_decrypt(std::move(str));
		});
	return result;
}


std::string RsaRelate::pub_encrypt(std::string &&clearText)
{
	if (m_pubkey.empty() || clearText.empty())
		return "";
	std::string strRet;
	int len = RSA_size(m_rsa_pub);


	char *encryptedText = (char *)malloc(len + 1);
	memset(encryptedText, 0, len + 1);

	int ret = RSA_public_encrypt(clearText.length(), (const unsigned char*)clearText.c_str(), (unsigned char*)encryptedText, m_rsa_pub, RSA_PKCS1_PADDING);
	if (ret >= 0)
		strRet = std::string(encryptedText, ret);

	free(encryptedText);
	return strRet;
}

std::string RsaRelate::pri_decrypt(std::string &&cipherText)
{
	if (m_prikey.empty() || cipherText.empty())
		return "";
	std::string strRet;
	int len = RSA_size(m_rsa_pri);
	char *decryptedText = (char *)malloc(len + 1);
	memset(decryptedText, 0, len + 1);

	int ret = RSA_private_decrypt(cipherText.length(), (const unsigned char*)cipherText.c_str(), (unsigned char*)decryptedText, m_rsa_pri, RSA_PKCS1_PADDING);
	if (ret >= 0)
		strRet = std::string(decryptedText, ret);

	free(decryptedText);
	return std::move(strRet);
}

std::string RsaRelate::pub_decrypt(std::string &&cipherText)
{
	if (m_pubkey.empty() || cipherText.empty())
		return "";
	std::string strRet;

	int len = RSA_size(m_rsa_pub);
	char *decryptedText = (char *)malloc(len + 1);
	memset(decryptedText, 0, len + 1);

	int ret = RSA_public_decrypt(cipherText.length(), (const unsigned char*)cipherText.c_str(), (unsigned char*)decryptedText, m_rsa_pub, RSA_PKCS1_PADDING);
	if (ret >= 0)
		strRet = std::string(decryptedText, ret);

	free(decryptedText);
	return std::move(strRet);
}

std::string RsaRelate::pri_encrypt(std::string &&clearText)
{
	if (m_prikey.empty() || clearText.empty())
		return "";
	std::string strRet;

	int len = RSA_size(m_rsa_pri);
	char *encryptedText = (char *)malloc(len + 1);
	memset(encryptedText, 0, len + 1);

	int ret = RSA_private_encrypt(clearText.length(), (const unsigned char*)clearText.c_str(), (unsigned char*)encryptedText, m_rsa_pri, RSA_PKCS1_PADDING);
	if (ret >= 0)
		strRet = std::string(encryptedText, ret);


	free(encryptedText);
	return std::move(strRet);
}


std::vector<std::string> RsaRelate::getBlockToEncryptVector(const std::string &clearText)
{
	std::vector<std::string>strsets;

	auto clearTextSize = clearText.size();
	auto blockSize = RSA_size(m_rsa_pub) - RSA_HEAD;


	int size = clearTextSize / blockSize + (clearTextSize % blockSize == 0 ? 0 : 1);
	strsets.reserve(size);

	int index = 0;
	while (index < (int)clearTextSize)
	{
		int len = index + blockSize > (int)clearTextSize ? clearTextSize - index : blockSize;
		strsets.push_back(clearText.substr(index, len));
		index += len;
	}
	return std::move(strsets);
}

std::vector<std::string> RsaRelate::getBlockToDecryptVector(const std::string &cipherText)
{
	std::vector<std::string>strsets;

	auto clearTextSize = cipherText.size();
	auto blockSize = RSA_size(m_rsa_pub);

	int size = clearTextSize / blockSize + (clearTextSize % blockSize == 0 ? 0 : 1);
	strsets.reserve(size);

	int index = 0;
	while (index < (int)clearTextSize)
	{
		int len = index + blockSize > (int)clearTextSize ? clearTextSize - index : blockSize;
		strsets.push_back(cipherText.substr(index, len));
		index += len;
	}
	return std::move(strsets);
}
