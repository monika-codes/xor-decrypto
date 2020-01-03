#include "validator.h"

namespace xorDecryptor
{
	GeneralValidator::GeneralValidator (Parameters parameters) :
		parameters(parameters) {}

	ValidatorResults GeneralValidator::validate (std::vector<char>*
		encryptedProgram, std::vector<char>* key) {

		ValidatorResults result;
		result.keyValid = false;

		for (int mzDisplacement = parameters.minMzDisplacement;
			mzDisplacement < parameters.maxMzDisplacment; mzDisplacement++) {
			if (validateOnce(encryptedProgram, key, mzDisplacement)) {
				result.mzDisplacement = mzDisplacement;
				result.keyValid = true;
				break;
			}
		}

		return result;
	}

	bool GeneralValidator::validateOnce (std::vector<char>* encryptedProgram,
		std::vector<char>* key, int mzDisplacement) {

		// Decryption of the COFF Header Location
		unsigned int coffHeaderLocation = (decryptByte(encryptedProgram, key, 
			parameters.coffPointerLocation + 1 - mzDisplacement) << 8) + 
			decryptByte(encryptedProgram, key, 
			parameters.coffPointerLocation - mzDisplacement);

		if (coffHeaderLocation - mzDisplacement <= 
			parameters.coffPointerLocation) return false;

		coffHeaderLocation -= mzDisplacement;

		// Checking if the COFF header is fully reachable
		if (encryptedProgram->size() < coffHeaderLocation + 4)
			return false;

		// Checking if the COFF header is correct
		if (decryptByte(encryptedProgram, key, coffHeaderLocation) == 'P' &&
			decryptByte(encryptedProgram, key, coffHeaderLocation + 1) == 'E' 
			&& decryptByte(encryptedProgram, key, coffHeaderLocation + 2) == '0'
			&& decryptByte(encryptedProgram, key, coffHeaderLocation + 3) == '0')
			return true;

		return false;
	}

	int GeneralValidator::decryptByte (std::vector<char>* encryptedProgram, 
		std::vector<char>* key, int byteToDecrypt) {

		return static_cast<int>((*encryptedProgram)[byteToDecrypt] ^ 
			(*key)[byteToDecrypt % key->size()]);
	}

} // namespace xorDecryptor