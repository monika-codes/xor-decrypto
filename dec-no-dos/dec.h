/** \file		dec.h
	\brief		File performing decryption
	\details	The decryption is based on the fact that the key used in XOR encryption with ECB mode, will be easily spotable over a string of bytes of 0. 
	\author		Monika Olchowik
	\date		12.2016
	\version	1.0
*/

#ifndef DEC
#define DEC

#include<algorithm>
#include<cstring>
#include<cstdio>


#ifndef BUFF_SIZE
// Maksymalna wielkosc bufora
#ifdef BIG_BUFF				/**< Big buffor size was only used for testing purposes only */
#define BUFF_SIZE 524288	/**< Buffer size */
#define OBR 524288			/**< The number of bytes in which we are looking for the key */
#else
#define BUFF_SIZE 1096
#define OBR 1024
#endif
#endif

#ifndef MAX_KEY_SIZE
#define MAX_KEY_SIZE 128	/**< Maximum viable key size */
#endif

#ifndef MAXN
#define MAXN 524288			/**< Variable used for the Hashmap */
#endif

#ifndef MAXP
#define MAXP 185531			/**< Variable used for the Hashmap */
#endif

#define EPSILON_COMPARE 0.0001

#include"vali.h"

/**
	/brief	Structer used for the hash of 
*/
struct hash_table
{
	unsigned int hash;		/**< Hash */
	int beg;				/**< First character */
	int type;				/**< How much of characters are included before the begining of the 'hash' */

	bool operator< (const hash_table&  ht) const
	{
		return hash < ht.hash;
	}
};



hash_table hash_sort[MAXN];			/**< Hashes of candidates for keys, that are rotated cyclically so that they begin from the first sign of the key*/
unsigned int hash_beg[BUFF_SIZE];	/**< Hashes of elements of the buff */
unsigned int p[BUFF_SIZE];			/**< Table used for calculating hashes */
int key_size;						/**< Key size */


/**
	\brief		Function creating a hash.
	\details	Currently the function is implemented in a simplistic, time efficient, proof-of-concept way.

	\arg		\c i	The beginning of the range, i <=j (!)
	\arg		\c j	The end of the range

	\return		\c unsigned int Hash
*/

inline unsigned int make_hash(const int& i, const int& j);

/**
	\brief		Function calculating a hash from a range that has been cyclically made to fit the key
	\details	The hash from a following elements: i - j, i - j - 1, ..., i - 1, i, i + 1, ..., i + key_size - j - 1, is calculated as if it beggins with i

	\arg		\c i	The beginning of the hash
	\arg		\c j	The amount of element before and after

	\return		\c unsigned int Hash
*/
inline unsigned int add_hash(const int& i, const int& j);


/**
	\brief		Function searching for a potential key of a given length

	\arg		\c buff				The bytes of the file
	\arg		\c key				Currently suspected key and the place where the key will be saved if found to be better than the current solution
	\arg		\c min				How many bytes will be checked
	\arg		\c ratio			The ratio of the occurance to the length of the current suspected key
	\arg		\c last_key_size	The length of the current key

	\return		\c bool				If found
*/
inline bool find_potential_key(const unsigned char buff[], unsigned char key[], const int& min, double& ratio, int& last_key_size, int& diff);


/**
	\brief		Finds the key in the file to decrypt it 

	\arg		\c buff				The bytes of the file
	\arg		\c key				The place where the key will be saved if found to be better than the current solution
	\arg		\c read_amount		How much has been read
	\arg		\c end_ratio		The resulting ratio of the occurances of the key to it's length

	\return		\c int				The length of the current key
*/

int make_key(const unsigned char buff[], unsigned char key[], int read_amount, double& end_ratio, int& diff);


/**
	\brief		Prints the key

	\arg		\c key				The key to be printed
	\arg		\c key_size			The length of the key

*/

void printkey(unsigned char key[], int key_size);

#endif
