#ifndef __RSARELATE_H__
#define __RSARELATE_H__


#include<vector>
#include<string>
#include "openssl/rsa.h"
#include "openssl/pem.h"

class RsaRelate 
{
public:
	RsaRelate(const std::string &pubKey, const std::string &priKey);
	~RsaRelate();
	std::string pub_block_encrypt(const std::string &clearText);
	std::string pri_stream_decrypt(const std::string &cipherText);

	std::string pub_stream_decrypt(const std::string &cipherText);
	std::string pri_block_encrypt(const std::string &clearText);

	static void generateRSAKey(std::string strKey[2], int bits = 2048, const std::string &pubPath = "pubkey.pem", const std::string&priPath="prikey.pem");

protected:
	std::string pub_block_decrypt(const std::string &cipherText);
	std::string pri_block_decrypt(const std::string &cipherText);
protected:
	std::string pub_encrypt(std::string &&clearText);
	std::string pri_decrypt(std::string &&cipherText);

	std::string pub_decrypt(std::string &&cipherText);
	std::string pri_encrypt(std::string &&clearText);
protected:
	std::vector<std::string> getBlockToEncryptVector(const std::string &clearText);
	std::vector<std::string> getBlockToDecryptVector(const std::string &cipherText);
protected:
	std::string m_pubkey;
	std::string m_prikey;
	
	RSA *m_rsa_pub;
	RSA *m_rsa_pri;

	std::string m_pubkey_deLeftString;
	std::string m_prikey_deLeftString;
};

#endif
