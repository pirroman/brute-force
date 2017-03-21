#pragma once

#include "CryptoPP/modes.h"
#include "CryptoPP/filters.h"
#include "CryptoPP/des.h"
#include "CryptoPP/cryptlib.h"
#include "CryptoPP/md5.h"
#include "CryptoPP/hex.h"
#include "CryptoPP/sha.h"
#include <fstream>
#include <iostream>
#include <thread>
#include <vector>
#include <algorithm>
#include <functional>

static constexpr unsigned DEFAULTLENGTH = 3;

class BruteForce
{
public:
	BruteForce(const std::string & filename, unsigned lengthKey);
	~BruteForce();

	bool run();
	std::string getKey() const;

	BruteForce(const BruteForce&) = delete;
	BruteForce & operator=(const BruteForce&) = delete;
private:
	bool isDecrypt{ false };
	std::string filename;
	std::string key;

	void _bruting(byte beginOffset, byte count);
	void _attemptDecrypt(std::vector<byte> & key);
	void _writeDecryptFile(const std::string & data);

	unsigned keyLength{ 0 };
	std::vector<byte> encryptedData;
	byte sha256[CryptoPP::SHA256::DIGESTSIZE]{ 0 };
	byte initVector[CryptoPP::DES_EDE2::BLOCKSIZE]{ 0 };

	enum class ALFABETFORKEYCUTS : byte 
	{ 
		NUMBERBEG		  = 0x30, NUMBEREND		    = 0x39,  
		ALFABETUPCASEBEG = 0x41, ALFABETUPCASEEND = 0x5A,
		ALFABETLOWCASEBEG = 0x61, ALFABETLOWCASEEND = 0x7A		 
	};

	static constexpr byte AMOUNTNUMBERS	 = 10;
	static constexpr byte AMOUUNTALFABET = 26;
	static constexpr double AMOUNTALFABETFORKEY = 62;
};


