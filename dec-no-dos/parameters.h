#ifndef PARAMETERS_H_
#define PARAMETERS_H_

namespace xorDecryptor
{
	struct Parameters
	{
		int coffPointerLocation;
		int maxMzDisplacment;
		int minMzDisplacement;
		int bytesToSearchForKeyIn;
		int maxKeyLength;
		int primeNumberForHashing;
	};

} // namespace xorDecryptor


#endif // PARAMETERS_H_	