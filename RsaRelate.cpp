#include"pch.h"
#include"RsaRelate.h"
#include "openssl/rsa.h"
#include "openssl/pem.h"
#include<algorithm>
#include<assert.h>

#define RSA_HEAD 11

RsaRelate::RsaRelate(const std::string &pubKey, const std::string &priKey):m_pubkey(pubKey)
,m_prikey(priKey)
, m_rsa_pub(nullptr)
, m_rsa_pri(nullptr)
{
	if (!pubKey.empty()) 
	{
		BIO *keybio = BIO_new_mem_buf((unsigned char *)m_pubkey.c_str(), -1);
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

void RsaRelate::generateRSAKey(std::string strKey[2], int bits, const std::wstring&pubPath, const std::wstring&priPath)
{
	// 公私密钥对    
	size_t pri_len;
	size_t pub_len;
	char *pri_key = NULL;
	char *pub_key = NULL;

	// 生成密钥对    
	RSA *keypair = RSA_generate_key(bits, RSA_F4, NULL, NULL);
	//RSA_generate_key_ex()
	BIO *pri = BIO_new(BIO_s_mem());
	BIO *pub = BIO_new(BIO_s_mem());

	PEM_write_bio_RSAPrivateKey(pri, keypair, NULL, NULL, 0, NULL, NULL);
	PEM_write_bio_RSAPublicKey(pub, keypair);

	// 获取长度    
	pri_len = BIO_pending(pri);
	pub_len = BIO_pending(pub);

	// 密钥对读取到字符串    
	pri_key = (char *)malloc(pri_len + 1);
	pub_key = (char *)malloc(pub_len + 1);

	BIO_read(pri, pri_key, pri_len);
	BIO_read(pub, pub_key, pub_len);

	pri_key[pri_len] = '\0';
	pub_key[pub_len] = '\0';

	// 存储密钥对    
	strKey[0] = pub_key;
	strKey[1] = pri_key;

	// 存储到磁盘（这种方式存储的是begin rsa public key/ begin rsa private key开头的）  
	FILE *pubFile = _wfopen(pubPath.c_str(), L"w");
	if (pubFile == NULL)
	{
		assert(false);
		return;
	}
	fputs(pub_key, pubFile);
	fclose(pubFile);

	FILE *priFile = _wfopen(priPath.c_str(), L"w");
	if (priFile == NULL)
	{
		assert(false);
		return;
	}
	fputs(pri_key, priFile);
	fclose(priFile);

	// 内存释放  
	RSA_free(keypair);
	BIO_free_all(pub);
	BIO_free_all(pri);

	free(pri_key);
	free(pub_key);
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
	//RSA *rsa = NULL;
	//BIO *keybio = BIO_new_mem_buf((unsigned char *)m_pubkey.c_str(), -1);
	// 此处有三种方法  
	// 1, 读取内存里生成的密钥对，再从内存生成rsa  
	// 2, 读取磁盘里生成的密钥对文本文件，在从内存生成rsa  
	// 3，直接从读取文件指针生成rsa  
	//RSA* pRSAPublicKey = RSA_new();
	//rsa = PEM_read_bio_RSAPublicKey(keybio, &rsa, NULL, NULL);

	int len = RSA_size(m_rsa_pub);


	char *encryptedText = (char *)malloc(len + 1);
	memset(encryptedText, 0, len + 1);

	// 加密函数  
	int ret = RSA_public_encrypt(clearText.length(), (const unsigned char*)clearText.c_str(), (unsigned char*)encryptedText, m_rsa_pub, RSA_PKCS1_PADDING);
	if (ret >= 0)
		strRet = std::string(encryptedText, ret);

	// 释放内存  
	free(encryptedText);
	//BIO_free_all(keybio);
	//RSA_free(rsa);

	return strRet;
}

std::string RsaRelate::pri_decrypt(std::string &&cipherText)
{
	if (m_prikey.empty() || cipherText.empty())
		return "";
	std::string strRet;
	//RSA *rsa = RSA_new();
	//BIO *keybio;
	//keybio = BIO_new_mem_buf((unsigned char *)m_prikey.c_str(), -1);

	// 此处有三种方法  
	// 1, 读取内存里生成的密钥对，再从内存生成rsa  
	// 2, 读取磁盘里生成的密钥对文本文件，在从内存生成rsa  
	// 3，直接从读取文件指针生成rsa  
	//rsa = PEM_read_bio_RSAPrivateKey(keybio, &rsa, NULL, NULL);

	int len = RSA_size(m_rsa_pri);
	char *decryptedText = (char *)malloc(len + 1);
	memset(decryptedText, 0, len + 1);

	// 解密函数  
	int ret = RSA_private_decrypt(cipherText.length(), (const unsigned char*)cipherText.c_str(), (unsigned char*)decryptedText, m_rsa_pri, RSA_PKCS1_PADDING);
	if (ret >= 0)
		strRet = std::string(decryptedText, ret);

	// 释放内存  
	free(decryptedText);
	//BIO_free_all(keybio);
	//RSA_free(rsa);

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
