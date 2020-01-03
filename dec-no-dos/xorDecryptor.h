#ifndef KEY_H_
#define KEY_H_

#include <vector>
#include <map>

#include "parameters.h"
#include "validator.h"

namespace xorDecryptor
{
	struct Location{
		int start;
		int rotation;
	};

	struct PotentialKey{
		std::vector<char> key;
		double ratio;
		int mzDisplacement;
		unsigned int hash;
	};

	class XorDecryptor{
	public:
		XorDecryptor(std::vector<char> encryptedText, Parameters parameters);
		std::pair<bool, std::vector<char> > findKey();

	private:
		Parameters parameters;
		GeneralValidator validator;

		std::vector<char> encryptedText;
		std::vector<unsigned int> hash;
		std::vector<int> prime;
		std::multimap<unsigned int, Location> hashTable;

		unsigned int rotatedKeyHash(int start, int rotation, int keySize);
		unsigned int standardKeyHash(int start, int end);
		int realKeyLength(std::vector<char> key);

		void generateHashTable(int keySize);
		PotentialKey generateCurrentKey(int start, int rotation, int keySize, 
			int count, unsigned int hash);

		PotentialKey findBestKeyForSetLength(int keySize);
	};

} // namespace xorDecryptor


#endif // KEY_H_	
