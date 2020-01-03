#ifndef VALIDATOR_H_
#define VALIDATOR_H_

#include<vector>
#include "parameters.h"

namespace xorDecryptor{
	struct ValidatorResults{
		bool keyValid;
		int mzDisplacement;
	};

	class GeneralValidator{
	public:
		static constexpr unsigned char kDosStub[] = 
			{ 0x4d, 0x5a, 0x90, 0, 0x3, 0, 0, 0, 0x4, 0, 0, 0, 0xff, 0xff };

		GeneralValidator(Parameters parameters);
		ValidatorResults validate (std::vector<char>* encryptedProgram, 
			std::vector<char>* key);
	
	protected:
		Parameters parameters;

		bool validateOnce (std::vector<char>* encryptedProgram, 
			std::vector<char>* key, int mzDisplacement);
		int decryptByte (std::vector<char> *encryptedProgram, 
			std::vector<char>* key, int byteToDecrypt);
	};
} // namespace xorDecryptor


#endif // VALIDATOR_H_	
