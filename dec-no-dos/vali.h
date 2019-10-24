/** \file		vali.h
    \brief		File containing validation functions for the solutions
	\author		Monika Olchowik
	\date		12.2016
	\version	1.0
*/

#ifndef EXE_VALIDATE
#define EXE_VALIDATE

#ifndef BUFF_SIZE
#define BUFF_SIZE 524288	/**< Buffer size */
#endif 

#ifndef MAX_KEY_SIZE
#define MAX_KEY_SIZE 128	/**< Maximum key size */
#endif 

#ifndef DOS_SIZE
#define DOS_SIZE 512	/**< DOS file size */
#endif 

#define NOT_FOUND 2048

unsigned const char DOS_STUB[] = {0x4d, 0x5a, 0x90, 0, 0x3, 0, 0, 0, 0x4, 0, 0, 0, 0xff, 0xff}; /**< Constant fragment of some EXE files - DOS stub */

#define dec_buff(x) (static_cast<unsigned char>(buff[v60 + x] ^ key[(v60 + x) % key_size])) /**< Decryption macro */

/**
	\brief		Function implementing the KMP algorithm. 
	\details	The function calculates the longest prefix-suffix, which is later used to determin the length of the suspected key.

	\arg		\c key	The key
	\arg		\c s	Current key length

	\return		\c int	The suspected key length
*/

int kmp(unsigned char* key, int s)
{
	int pref_suf[s];
	int prev = 0;
	int i = 1;

	pref_suf[0] = 0;

	// Creation of prefix-suffix table
	while(i < s)
	{
		if(key[i] == key[prev])
			pref_suf[i++] = ++prev;
	
		else
		{
			if(prev != 0)
				prev = pref_suf[prev - 1];
			else
				pref_suf[i++] = 0;
		}
	}
	
	// Rerurnig the length of the key minus the longest prefix-suffix
	// This way the shortest key is found
	return s - pref_suf[s - 1]; 
	
}


/**
	\brief		Function validating if the file is a correct EXE file for a set number of bytes ignored
	\details	The function uses the key asspects of the structure of an EXE File, including the COFF header

	\arg		\c buff		BUFF_SIZE bytes from the header 
	\arg		\c key		Key no longer than MAX_KEY_SIZE, there is no point in checking for keys longer than MAX_KEY_SIZE
	\arg		\c key_size	Key length
	\arg		\c diff		Number of bytes that are ignored

	\return		\c bool		If the file can be an exe file
*/
bool validate_once(const unsigned char buff[BUFF_SIZE], const unsigned char key[MAX_KEY_SIZE], int key_size, int diff)
{
		int v60;	/**< The value of the 60th byte - begining of the PE header */
		v60 = ((static_cast<int>(buff[(61 - diff)] ^ key[((61 - diff)) % key_size])) << 8) + (static_cast<int>(buff[(60 - diff)] ^ key[((60 - diff)) % key_size])); 
		v60 = v60 - diff; 	


		if(v60 + 0x19 > BUFF_SIZE) return false;


		// COFF header - PE00 Check
		if(dec_buff(0) != 'P' || dec_buff(1) != 'E' || dec_buff(2) || dec_buff(3))
			return false;

		return true;
}


/**
	\brief		Function validating if the file is a correct EXE file
	\details	The function uses the key asspects of the structure of an EXE File, including the COFF header

	\arg		\c buff		BUFF_SIZE bytes from the header
	\arg		\c key		Key no longer than MAX_KEY_SIZE, there is no point in checking for keys longer than MAX_KEY_SIZE
	\arg		\c key_size	Key length

	\return		\c bool		The offset of the file (missing bytes, or added bytes) OR NOT_FOUND if suspected that it is not an EXE file
*/

int validate(const unsigned char buff[BUFF_SIZE], const unsigned char key[MAX_KEY_SIZE], int key_size)
{
	for(int i = -8; i < 9; i++)
		if(validate_once(buff, key, key_size, i))
			return i;
	return NOT_FOUND;
}


#endif
