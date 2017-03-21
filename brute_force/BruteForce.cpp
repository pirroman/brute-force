#include "BruteForce.h"

BruteForce::BruteForce(const std::string & filename, unsigned lengthKey) : 
	keyLength(lengthKey)
{
	this->filename = filename;
	std::ifstream encryptedFile(filename, std::ios::ate | std::ios::binary);
	encryptedFile.exceptions(std::ios::badbit | std::ios::failbit);

	if (!encryptedFile.is_open())
		throw std::ifstream::failure("file not found!");

	//get size file and reading SHA256
	size_t fsize = encryptedFile.tellg();
	encryptedFile.seekg( - CryptoPP::SHA256::DIGESTSIZE, std::ios::cur);
	encryptedFile.read((char*)sha256, CryptoPP::SHA256::DIGESTSIZE);

	//reading initialize vector
	encryptedFile.seekg(std::ios::beg);
	encryptedFile.read((char*)initVector, sizeof(initVector));

	//reading encrypted data
	size_t encryptedDataSize = fsize - encryptedFile.tellg() - CryptoPP::SHA256::DIGESTSIZE;
	encryptedData.resize(encryptedDataSize);
	encryptedFile.read((char*)encryptedData.data(), encryptedDataSize);

	encryptedFile.close();
}

bool BruteForce::run()
{
	auto HardwareThreads = std::thread::hardware_concurrency();
	std::vector<std::thread> threads(HardwareThreads - 1);
	byte chunkData = round(AMOUNTALFABETFORKEY / HardwareThreads);
	byte begOffset	= 0;
	
	for (unsigned i = 0; i < HardwareThreads - 1; ++i)
	{
		threads[i] = std::thread(&BruteForce::_bruting, this, begOffset, chunkData);
		begOffset += chunkData;
	}
	_bruting(begOffset, AMOUNTALFABETFORKEY - begOffset);
	std::for_each(threads.begin(), threads.end(), std::mem_fn(&std::thread::join));

	return isDecrypt;
}

void BruteForce::_bruting(byte beginOffset, byte offset)
{
	std::vector<byte> key(keyLength, static_cast<byte>(ALFABETFORKEYCUTS::NUMBERBEG));

	if (beginOffset >= AMOUNTNUMBERS + AMOUUNTALFABET)
		key[0] = static_cast<byte>(ALFABETFORKEYCUTS::ALFABETLOWCASEBEG) + (beginOffset - AMOUUNTALFABET - AMOUNTNUMBERS);
	else if (beginOffset >= AMOUNTNUMBERS)
		key[0] = static_cast<byte>(ALFABETFORKEYCUTS::ALFABETUPCASEBEG) + (beginOffset - AMOUNTNUMBERS);
	else
		key[0] += beginOffset;

	for (byte iter = 0; !isDecrypt && iter < offset;)
	{
		_attemptDecrypt(key);
		for (int i = this->keyLength - 1; i >= 0; --i)
		{
			++key[i];
			if (i == 0)
				++iter;

			if (key[i] > static_cast<byte>(ALFABETFORKEYCUTS::ALFABETLOWCASEEND))
			{
				key[i] = static_cast<byte>(ALFABETFORKEYCUTS::NUMBERBEG);
				continue;
			}
			else if (key[i] < static_cast<byte>(ALFABETFORKEYCUTS::ALFABETLOWCASEBEG) && key[i] > static_cast<byte>(ALFABETFORKEYCUTS::ALFABETUPCASEEND))
			{
				key[i] = static_cast<byte>(ALFABETFORKEYCUTS::ALFABETLOWCASEBEG);
				break;
			}
			else if (key[i] < static_cast<byte>(ALFABETFORKEYCUTS::ALFABETUPCASEBEG) && key[i] > static_cast<byte>(ALFABETFORKEYCUTS::NUMBEREND))
			{
				key[i] = static_cast<byte>(ALFABETFORKEYCUTS::ALFABETUPCASEBEG);
				break;
			}
			else
			{
				break;
			}
		}

	}
}

void BruteForce::_attemptDecrypt(std::vector<byte> & key)
{	
	std::string decryptData;
	CryptoPP::CBC_Mode< CryptoPP::DES_EDE2 >::Decryption decryptor;
	byte md5Key[CryptoPP::MD5::DIGESTSIZE]{ 0 };
	
	CryptoPP::MD5().CalculateDigest(md5Key, key.data(), key.size());
	decryptor.SetKeyWithIV(md5Key, CryptoPP::MD5::DIGESTSIZE, initVector);
	
	CryptoPP::StreamTransformationFilter TransFilter(decryptor, new CryptoPP::StringSink(decryptData), CryptoPP::BlockPaddingSchemeDef::NO_PADDING);
	TransFilter.Put(encryptedData.data(), encryptedData.size(), true);
	TransFilter.MessageEnd();

	byte sha256OfDecyptData[CryptoPP::SHA256::DIGESTSIZE]{ 0 };
	CryptoPP::SHA256().CalculateDigest(sha256OfDecyptData, reinterpret_cast<const byte*>(decryptData.c_str()), decryptData.length());
	if (!memcmp(sha256, sha256OfDecyptData, CryptoPP::SHA256::DIGESTSIZE))
	{
		this->key = std::move(std::string(key.begin(), key.end()));
		this->isDecrypt = true;
		_writeDecryptFile(decryptData);
	}
}

void BruteForce::_writeDecryptFile(const std::string & data)
{
	auto startExtension = filename.find_last_of('.');

	std::string decryptFileName;
	if (startExtension != std::string::npos)
		decryptFileName = filename.substr(0, startExtension) + "_decrypted" + filename.substr(startExtension);
	else
		decryptFileName = filename + "_decrypted";

	std::ofstream decryptFile(decryptFileName, std::ios::binary);
	decryptFile.exceptions(std::ios::badbit | std::ios::failbit);

	if (!decryptFile.is_open())
		throw std::ifstream::failure("bad open file!");

	decryptFile.write((char*)data.c_str(), data.length());
	decryptFile.close();
}

std::string BruteForce::getKey() const
{
	return key;
}

BruteForce::~BruteForce()
{
}
