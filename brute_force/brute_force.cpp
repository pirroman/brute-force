// brute_force.cpp: определяет точку входа для консольного приложения.
//
#include "BruteForce.h"
#include <iostream>
#include <algorithm>
#include <string>

bool is_number(const std::string& s)
{
	return !s.empty() && std::find_if(s.begin(),
		s.end(), [](char c) { return !isdigit(c); }) == s.end();
}

int main(int argc,const char *argv[])
{
	if (argc < 2)
	{
		std::cout << "Usage: " << argv[0] << " filename [keyLength]" << std::endl;
		return 0;
	}

	unsigned keyLength = DEFAULTLENGTH;

	if (argc > 2)
	{
		std::string temp(argv[2]);
		if (is_number(temp))
			keyLength = std::stoi(temp);
	}
	try {
		BruteForce brute(argv[1], keyLength);
		//auto beg = std::chrono::system_clock::now();
		brute.run();
		//auto end = std::chrono::system_clock::now();
		//std::cout << "seconds: " << std::chrono::duration_cast<std::chrono::milliseconds>(end - beg).count() << std::endl;
		std::cout << "key: " << brute.getKey() << std::endl;
	}
	catch (std::ifstream::failure &)
	{
		std::cout << "file invalid name!" << std::endl;
	}

    return 0;
}

