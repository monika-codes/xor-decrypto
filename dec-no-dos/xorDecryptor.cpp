#include "xorDecryptor.h"

namespace xorDecryptor
{
	unsigned int XorDecryptor::standardKeyHash(int start, int end){
		if (start == 0) {
			return hash[end];
		}

		return hash[end] - hash[start - 1] * prime[end - start + 1];
	}

	XorDecryptor::XorDecryptor(std::vector<char> encryptedText, Parameters parameters):
		validator(parameters)
	{
		this->encryptedText = encryptedText;
		this->parameters = parameters;

		hash.push_back(encryptedText[0]);
		int bytesToHash = std::min(parameters.bytesToSearchForKeyIn, 
			static_cast<int>(encryptedText.size()));
		for (int i = 1; i < bytesToHash; i++) {
			hash.push_back(hash[i - 1] * parameters.primeNumberForHashing 
				+ encryptedText[i]);
		}

		prime.push_back(1);
		for (int i = 1; i < bytesToHash; i++) {
			prime.push_back(prime[i - 1] * parameters.primeNumberForHashing);
		}

	}

	std::pair<bool, std::vector<char> > XorDecryptor::findKey()
	{
		PotentialKey bestKey;
		bestKey.ratio = -1;
		bool valid = false;

		for (int i = 0; i < parameters.maxKeyLength; i++) {
			PotentialKey newKey = findBestKeyForSetLength(i);
			if (newKey.ratio < bestKey.ratio) {
				bestKey = newKey;
				valid = true;
			}
		}

		return std::make_pair(valid, bestKey.key);
	}

	unsigned int XorDecryptor::rotatedKeyHash(int start, int rotation, int keySize){
		if (rotation != 0) {
			return standardKeyHash(start, start + keySize - rotation - 1) * 
				prime[rotation] + standardKeyHash(start - rotation, start - 1);
		}

		return standardKeyHash(start, start + keySize - 1);
	}

	int XorDecryptor::realKeyLength(std::vector<char> key)
	{
		int start = 0;
		int end = static_cast<int>(key.size());

		int keyLength = end - start;
		int prefSuf[keyLength];
		int prev = 0;
		int i = 1;

		prefSuf[0] = 0;

		// Creation of prefix-suffix table
		while (i < keyLength) {
			if (key[start + i] == key[start + prev]) {
				prefSuf[i++] = ++prev;
			} else {
				if (prev != 0) {
					prev = prefSuf[prev - 1];
				} else {
					prefSuf[i++] = 0;
				}
			}
		}

		// Rerurnig the length of the key minus the longest prefix-suffix
		// This way the shortest key is found
		return static_cast<int>(key.size()) - prefSuf[keyLength - 1];

	}

	void XorDecryptor::generateHashTable(int keySize){
		hashTable.clear();

		int bytesToLookForKey = std::min(parameters.bytesToSearchForKeyIn, 
			static_cast<int>(hash.size()));
				
		for (int i = keySize; i < bytesToLookForKey - keySize - 1;
			i += keySize){

			for (int j = 0; j <= keySize - 1; j++){
				Location location;
				location.start = i;
				location.rotation = j;

				hashTable.insert(std::pair<unsigned int, Location> 
					(rotatedKeyHash(i, j, keySize), location));
			}
		}
	}

	PotentialKey XorDecryptor::generateCurrentKey(int start, int rotation, int keySize, 
		int count, unsigned int hash){

		PotentialKey newKey;

		for (int i = 0; i < keySize; i++){
			if (i < keySize - rotation) {
				newKey.key.push_back(encryptedText[start + i]);
			} else {
				newKey.key.push_back(encryptedText[start - keySize + i]);
			}
		}

		newKey.ratio = static_cast<double>(this->realKeyLength(newKey.key)) 
			/ count; // doci¹æ klucz
		newKey.hash = hash;

		return newKey;
	}

	PotentialKey XorDecryptor::findBestKeyForSetLength(int keySize){
		generateHashTable(keySize);

		PotentialKey prevKey;
		prevKey.hash = hashTable.begin()->first - 1;
		PotentialKey bestKey;
		bestKey.ratio = -1;

		int count = 0;

		for (std::multimap<unsigned int, Location>::iterator i = hashTable.begin();
			i != hashTable.end(); i++) {

			PotentialKey currentKey = generateCurrentKey(i->second.start,
				i->second.rotation, keySize, count, i->first);

			if (prevKey.hash == currentKey.hash) {
				count++;
				break;
			}

			if (bestKey.ratio < currentKey.ratio) {
				ValidatorResults validatorResult = validator.validate(
					&encryptedText, &currentKey.key);

				if (validatorResult.keyValid) {
					currentKey.mzDisplacement = validatorResult.mzDisplacement; 
					bestKey = currentKey;
				}
			}

			prevKey = currentKey;
			count = 0;

		}
		return bestKey;
	}
} // namespace xorDecryptor