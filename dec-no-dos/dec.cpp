/** \file		dec.cpp
	\brief		File performing decryption
	\details	The decryption is based on the fact that the key used in XOR encryption with ECB mode, will be easily spotable over a string of bytes of 0.
	\author		Monika Olchowik
	\date		12.2016
	\version	1.0
*/

#include "dec.h"

inline unsigned int make_hash(const int& i, const int& j)
{
	if (i == 0) return hash_beg[j];
	return hash_beg[j] - hash_beg[i - 1] * p[j - i + 1];
}


inline unsigned int add_hash(const int& i, const int& j)
{
	if (j != 0)
		return make_hash(i, i + key_size - j - 1) * p[j] + make_hash(i - j, i - 1);
	return make_hash(i, i + key_size - 1);
}


inline bool find_potential_key(const unsigned char buff[], unsigned char key[], const int& min, double& ratio, int& last_key_size, int& diff)
{

	// Determine potential keys
	int l = 0;	// Amount of different hashes
	for (int i = key_size; i < min - key_size - 1; i += key_size)
	{
		for (int j = 0; j < key_size - 1; j++)
		{
			hash_sort[l].beg = i;
			hash_sort[l].type = j;
			hash_sort[l++].hash = add_hash(i, j);
		}

		hash_sort[l].beg = i;
		hash_sort[l].type = key_size - 1;
		hash_sort[l++].hash = add_hash(i, key_size - 1);
	}

	// Sorting of the table
	std::stable_sort(hash_sort, hash_sort + l);

	unsigned int last_hash = hash_sort[0].hash - 1;		// The last hash viewed
	int key_count = -1;									// The biggest number of occurences
	int hash_count = 0;									// The number of occurences of hash		
	unsigned char key_temp[MAX_KEY_SIZE]; 				// Temporary key variable

	// Searching for the key 
	// while going through the structure containing hashes

	for (int j = 0; j < l; j++)
	{
		if (last_hash != hash_sort[j].hash)
		{
			last_hash = hash_sort[j].hash;
			hash_count = 1;
			continue;
		}

		hash_count++;

		// Choses the last of the hashes of the same length 
		// Counting the occurances of the hash in count variable
		if (j == l - 1 || hash_sort[j].hash != hash_sort[j + 1].hash)
		{
			// On the basis of each hash that occurs more than once create a key
			for (int i = 0; i < key_size; i++)
			{
				if (i < key_size - hash_sort[j].type)
					key_temp[i] = buff[hash_sort[j].beg + i];
				else
					key_temp[i] = buff[hash_sort[j].beg - key_size + i];
			}


			int temp_diff;

			// Check if the key is viable
			if ((temp_diff = validate(buff, key_temp, key_size)) != NOT_FOUND)
			{
				if (key_size == last_key_size && key_count > hash_count) continue;
				double hash_ratio = (static_cast<double>(hash_count)) / key_size;


				if (ratio > hash_ratio + EPSILON_COMPARE)
					continue;

				diff = temp_diff;
				ratio = hash_ratio;

				last_key_size = kmp(key_temp, key_size);
				key_count = hash_count;

				// Overwrite the key
				memcpy(key, key_temp, sizeof(key_temp));

			}

		}

	}

	// The key of set length was not found 
	if (key_count == -1) return false;

	return true;

}


int make_key(const unsigned char buff[], unsigned char key[], int read_amount, double& end_ratio, int& diff)
{
	// How much of bytes can be analysed when looking for the key
	int min = OBR;
	if (min > read_amount)
		min = read_amount;

	// Creation of the hashes for buff
	hash_beg[0] = buff[0];
	for (int i = 1; i < min; i++) hash_beg[i] = hash_beg[i - 1] * MAXP + buff[i];

	int last_key_size = -1;		// The length of the best key
	double ratio = 0;			// Ratio for the key


	// Finding the key
	for (int i = 1; i <= MAX_KEY_SIZE; i++)
	{
		key_size = i;
		find_potential_key(buff, key, min, ratio, last_key_size, diff);
	}

	key_size = last_key_size;

	if (last_key_size <= 0)
		return -1;


	end_ratio = ratio;

	return key_size;
}


void printkey(unsigned char key[], int key_size)
{
	printf("{ \"key_size\": %d, \"key\": ", key_size);
	for (int i = 0; i < key_size; i++)
		printf("%02X", key[i]);
	printf("}");
	printf("\n");

}
