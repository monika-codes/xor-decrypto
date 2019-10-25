/** 	\file		dec_no_dos.cpp
	\brief		Console intereface to run the program
	\details	The aim of the program is to decrypt an EXE file encrypted with XOR with ECB mode. It is based on the fact that the key used in XOR encryption with ECB mode, will be easily spotable over a string of bytes of 0.
	\author		Monika Olchowik
	\date		12.2016
	\version	1.0
*/
#include<getopt.h>
#include<unistd.h>
#include<cmath>
#include<ctime>
#include<cstdio>
#include"dec.h"

using namespace std;

/**
	\brief		Function printing the usage message of the function
	
	\arg		\c	argv	Arguments containing the name of the file
*/
void printf_usage(char** argv)
{
	printf("Usage:\n\t %s [FILE_ENCRYPTED] [FILE_DECRYPTED] [OPTIONS] ... \n", argv[0]);
}


/**
	\brief		Function used to get the arguments from the console
	\details	The function calculates the longest prefix-suffix, which is later used to determin the length of the suspected key.

	\arg		\c argc			Count of arguments
	\arg		\c argv			Values of the arguments
	\arg		\c text_size	The amount to be read
	\arg		\c reverse		Should the file be reversed
	\arg		\c fenc			File with the encrypted data
	\arg		\c fdec			File where the decrypted data should be saved (if successful)

	\return		\c int	The suspected key length
*/
int set_parameters(int argc, char** argv, int& text_size, bool& reverse, char* fenc, char* fdec)
{
	struct option long_options[] =
	{
		{"size",	required_argument, 	0, 	's'},
		{"reverse",	no_argument,	 	0, 	'r'},
		{"help", 	no_argument, 		0, 	'h'},
		{"version", 	no_argument, 		0, 	'v'},
		{0,		0,			0,	0}

	};

	// Default values
	text_size = 16000;

	int c;			
	int optionid = 0;	
	int check = 0;

	// Getting the options
	while((c = getopt_long(argc, argv, "hvrs:", long_options, &optionid)) != -1)
	{
		// Help
		if(c == 'h')
		{
			printf_usage(argv);
			return -1;
		}

		// Version
		if(c == 'v')
		{
			printf("v. 1.1\nAuthor: Monika Olchowik\n");
			return -1;
		}

		//Buffor_size
		if(c == 's')
		{
			text_size = atoi(optarg);
			if(text_size > BUFF_SIZE)
			{
				printf("Size too large.\n");
				printf_usage(argv);
				return -1;
			}
			continue;
		}

		// If the file should be reversed
		if(c == 'r')
			reverse = true;		
	}	
	return 0;
}

int main(int argc, char** argv)
{
	int text_size;				
	int read_counter = 0;
	bool reverse;
	char* fenc = argv[1];
	char* fdec = argv[2];

	unsigned char buff[BUFF_SIZE];		// Buffer in which the data will be kept
	unsigned char key[MAX_KEY_SIZE];	// The most probable key

	buff[0] = '0';

	if(set_parameters(argc, argv, text_size, reverse, fenc, fdec) == -1)
		return -1;

	// Helpful for hashing algorithm used
	p[0] = 1;
	for(int i = 1; i < BUFF_SIZE; i++) 
		p[i] = p[i - 1] * MAXP;

	// Reading (and possibly reversing the file)
	FILE* f_read = fopen(fenc, "rb");
	if(f_read == NULL) 
	{
		printf_usage(argv);
		return 0;
	}

	read_counter = fread(buff, sizeof(char), BUFF_SIZE, f_read);

	if(reverse)
	{
		for(int i = 0; i < read_counter / 2; i++)
		{
			unsigned char temp = buff[i];
			buff[i] = buff[read_counter - i - 1];
			buff[read_counter - i - 1] = temp;
		}
	
	}
	
	if(text_size > read_counter) 
		text_size = read_counter;

	// Finding keys
	double ratio;
	int diff;
	int key_length = make_key(buff, key, text_size, ratio, diff);

	if(key_length == -1) 
		return ERR_NO_KEY;

	printkey(key, key_length);

	// Decrypting file
	FILE* f_write = fopen(fdec, "wb");
	if(f_write == NULL) 
	{
		printf_usage(argv);
		return 0;
	}
	
	for(int i = 0; i < read_counter; i++)
		buff[i] = static_cast<char>(buff[i] ^ key[i % key_size]);

    
	// Saving the file
	if(diff > 0) 
		fwrite(DOS_STUB, sizeof(char), diff, f_write);

	if (diff < 0) 
		fwrite(buff - diff, sizeof(char), read_counter, f_write);
	else 
		fwrite(buff, sizeof(char), read_counter, f_write);

	read_counter -= BUFF_SIZE;

	fclose(f_write);
	fclose(f_read);
	
	return 0;
}

