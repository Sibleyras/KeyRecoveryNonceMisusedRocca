#include "rocca.h"

#include <stdio.h>
#include <time.h>

#define MAX_GUESSOUTPUT 250
#define MAX_GUESS 2050

// Fill the key with random bits.
void randkey(uint8_t key[32], const int seed){
    srand(seed);
    for(int i = 0; i < 32; i++)
        key[i] = rand();
}

// Load the rocca_state dst with the byte values contained in src.
void loadroccastate(rocca_state dst, const int src[8][16]){
    uint8_t tmp[16];
    for(int i = 0; i < 8; i++){
        for(int j = 0; j < 16; j++)
            tmp[j] = (uint8_t) src[i][j];
        dst[i] = load_u128(tmp);
    }
}

// Print the content of a char array.
void printuint8arr(int len, const uint8_t state[len]){
    for(int i = 0; i < len; i++){
        printf("%02x", 0xFF&state[i]);
        if(i < len-1) printf(" ");
    }
}

// Load the 16 bytes contained in u128 src to integer array dst.
void u128_to_arr(int dst[16], const u128 src){
    uint8_t tmp[16]; store_u128(tmp, src);
    for(int i = 0; i < 16; i++)
        dst[i] = tmp[i];
}

// Apply a function fun that takes a char array as input to an integer array dst.
void uint_fun_for_int(int len, int dst[len], void (*fun)(uint8_t*)){
    uint8_t tmp[len];
    for(int i = 0; i < 16; i++)
        tmp[i] = (uint8_t) dst[i];

    fun(tmp);

    for(int i = 0; i < 16; i++)
        dst[i] = (int) tmp[i];
}

// Print all possible state for all 4 columns. That is, every combination of one value of each 4 columns represent a possibility encoded in guessoutput. 
void printguessoutput(int maxguess, const int guessoutput[4][maxguess][4]){
    int i = 0;
    bool hasended[4] = {false, false, false, false};
    while(!hasended[0] || !hasended[1] || !hasended[2] || !hasended[3]){
        printf("%4d : ", i);
        for(int j = 0; j < 4; j++){
            for(int k = 0; k < 4; k++){
                if(hasended[j])
                    printf("--");
                else
                    printf("%02x", guessoutput[j][i][k]);
                if(k < 3) printf(".");
            }
            printf(" / ");
        }
        printf("\n");
        if(++i >= maxguess){
            printf("Not Enough Space\n");
            return;
        }
        for(int j = 0; j < 4; j++){
            if(!hasended[j])
                hasended[j] = (guessoutput[j][i][0] == -1);
        }
    }
}

// Print all possible state for all dimi (dimi = 16 for a full AES state, 4 for a column) char. That is, every combination of one value of each dimi positions represent a possibility encoded in guessinput. 
void printguess(int dimi, int dimj, const int guessinput[dimi][dimj][2]){
    for(int i = 0; i < dimi; i++){
        printf("%2d : ", i);
        for(int j = 0; j < dimj; j++){
            if (guessinput[i][j][0] == -1){
                continue;
            }
            if(j > 0) printf(" OU ");
            printf("%02x/%02x", guessinput[i][j][0], guessinput[i][j][1]);
        }
        printf("\n");
    }
}

// Initialize the table of possibility sboxDDT. Given input/output difference patern din/dout, the possible starting states are all sboxDDT[din][dout][i] that are not -1.
void initialize_sboxddt(int sboxDDT[256][256][2]) {
	for(int i = 0; i<256; i++){
        for(int j = 0; j<256; j++){
            for(int k = 0; k<2; k++){
                sboxDDT[i][j][k] = -1; // negative means no value
            }
        }
    }
    int MAXERROR = 20;
    for(int din = 1; din<256; din++){
        for(int i = 0; i<256; i++){
            int dout = aes_sbox[i]^aes_sbox[i^din];
            if(sboxDDT[din][dout][0] == -1){
                sboxDDT[din][dout][0] = i;
            } else if(((sboxDDT[din][dout][0]^din) != i) && (sboxDDT[din][dout][1] == -1)){
                sboxDDT[din][dout][1] = i;
            } else if(((sboxDDT[din][dout][0]^din) != i) && ((sboxDDT[din][dout][1]^din) != i)){
                printf("Initialization error i: %x, din: %x, dout: %x, dindout0: %x, dindout1: %x, eval: %x\n",i,din,dout, sboxDDT[din][dout][0], sboxDDT[din][dout][1], (sboxDDT[din][dout][0]^din) != i); //There is more than two possibilities.
                if(--MAXERROR == 0)
                    return;
            }
        }
    }
	/* 0 is a special case */
	sboxDDT[0][0][0] = 256;
}

// Perform a XOR operation on all possibilities represented by guess_to_xor with const_to_xor and store it in guess.
void guess_xor_const(int dimi, int dimj, int dimk, int guess[dimi][dimj][dimk], int guess_to_xor[dimi][dimj][dimk], uint8_t const_to_xor[dimi]){
    for(int i = 0; i < dimi; i++)
        for(int j = 0; j < dimj; j++)
            for(int k = 0; k < dimk; k++)
                    guess[i][j][k] = guess_to_xor[i][j][k] == -1 ? -1 : guess_to_xor[i][j][k] ^ const_to_xor[i];
}

// Build guessinputxor that represents all possibilities resulting on XORing each possibility represented by guessinput1 with each possibility represented by guessinput2. 
void xor_guess_input(int guessinputxor[16][4][2], int guessinput1[16][2][2], int guessinput2[16][2][2]){
    for(int i = 0; i < 16; i++)
        for(int j = 0; j < 4; j++)
            for(int k = 0; k < 2; k++)
                guessinputxor[i][j][k] = -1; // initialize array to -1 .
    
    int jxor, din;
    for(int i = 0; i < 16; i++){
        jxor = 0;
        for(int j1 = 0; j1 < 2; j1++){
            for(int j2 = 0; j2 < 2; j2++){
                if(guessinput1[i][j1][0] == -1 || guessinput2[i][j2][0] == -1)
                        continue;
                din = guessinput1[i][j1][0]^guessinput1[i][j1][1];
                guessinputxor[i][jxor][0] = guessinput1[i][j1][0]^guessinput2[i][j2][0];
                guessinputxor[i][jxor][1] = guessinputxor[i][jxor][0] ^ din;
                jxor++;
            }
        }
    }
}

/*  Increment the index cycling of every possibilities and store the next possibility to next. Return false if no next element, true otherwise.
    Inputing a {0,0,0,-1} index will output the first element. */
bool iter_guessout(int index[4], int next[16], int maxlen, const int guessout[4][maxlen][4]){
    for (int i = 3; i >= 0; i--){
        index[i]++;
        if(index[i] < maxlen && guessout[i][index[i]][0] != -1)
            break;
        index[i] = 0;
        if(i == 0)
            return false;
    }
    for (int i = 0; i < 4; i++)
        for (int j = 0; j < 4; j++)
            next[i*4+j] = guessout[i][index[i]][j];
    return true;
}

// Apply the subbytes AES operation on each possibility stored in guess.
void guessinput_subbytes(int dimj, int dimk, int guess[16][dimj][dimk]){
    for(int i = 0; i < 16; i++)
        for(int j = 0; j < dimj; j++)
            for(int k = 0; k < dimk; k++)
                    guess[i][j][k] = guess[i][j][k] == -1 ? -1 : aes_sbox[guess[i][j][k]];
}

// Swap the values of two integers.
void int_swap(int* a, int* b){
    int c = *a; *a = *b; *b = c;
}

// Swap the values of two guessed char.
void guess_swap(int dimj, int dimk, int guess1[dimj][dimk], int guess2[dimj][dimk]){
    for(int j = 0; j < dimj; j++)
        for(int k = 0; k < dimk; k++)
            int_swap(&guess1[j][k], &guess2[j][k]);
}

// Apply the shiftrow AES operation on each possibility stored in guess.
void guessinput_shiftrow(int dimj, int dimk, int guess[16][dimj][dimk]){
    guess_swap(dimj, dimk, guess[1], guess[5]); guess_swap(dimj, dimk, guess[5], guess[9]); guess_swap(dimj, dimk, guess[9], guess[13]);
    guess_swap(dimj, dimk, guess[2], guess[10]); guess_swap(dimj, dimk, guess[6], guess[14]);
    guess_swap(dimj, dimk, guess[11], guess[15]); guess_swap(dimj, dimk, guess[7], guess[11]); guess_swap(dimj, dimk, guess[3], guess[7]);      
}

// Print current multi-array index for debugging purpose.
void printindex(const int index[4][2]){
    printf("{ ");
    for(int i = 0; i < 4; i++){
        printf("{%d, %d} ", index[i][0], index[i][1]);
    }
    printf("}");
}

// modify index to point to the next value of 4-valued guessinput.
bool incrementindex(int dimj, int index[4][2], const int guessinput[4][dimj][2]){ 
    for(int i = 3; i >= 0; i--){
        ++index[i][1];
        if( index[i][1] < 2 && guessinput[i][index[i][0]][index[i][1]] != -1 ){
            return true;
        }
        index[i][1] = 0;

        ++index[i][0];
        if( index[i][0] < dimj && guessinput[i][index[i][0]][index[i][1]] != -1 ){
            return true;
        }
        index[i][0] = 0;
    }
    return false;
}

/*
    Apply the mix_column AES operation on each possibility stored in guessin and store the result in guessout.
    Notice that we can't store the resulting possibilities of each 4 char independently but we have to store a full column guesses for each possibility encoded by guessin.
*/
void guessoutput_mix_column(int dimj, int guessout[MAX_GUESSOUTPUT][4], const int guessin[4][dimj][2]){
    int indexin[4][2] = {0};
    uint8_t to_mix[4];

    int iout = 0;
    do {
        for(int j = 0; j < 4; j++){
            to_mix[j] = (uint8_t) guessin[j][indexin[j][0]][indexin[j][1]];
        }
        gmix_column(to_mix);
        for(int j = 0; j < 4; j++){
            guessout[iout][j] = (int) to_mix[j];
        }
    } while(++iout < MAX_GUESSOUTPUT && incrementindex(dimj, indexin, guessin)); // increment both indexes and test for end.

    if(iout >= MAX_GUESSOUTPUT){
        printf("Reach end of MAX_GUESSOUTPUT entries.\n");
        return;
    }
    for(int j = 0; j < 4; j++){
        guessout[iout][j] = -1;
    }
}

/*
    Apply a full AES round operation on each possibility stored in guessinput and store the result in guessoutput.
    Due to the mix column operation we can't store the resulting possibilities of each 16 char independently but we have to store multiple guesses for each 4 columns.
*/
void guess_output_aes_from_input(int dimj, int guessoutput[4][MAX_GUESSOUTPUT][4], const int guessinput[16][dimj][2]){
    int guessshiftsub[16][dimj][2];
    for(int i = 0; i < 16; i++)
        for(int j = 0; j < dimj; j++)
            for(int k = 0; k < 2; k++)
                guessshiftsub[i][j][k] = guessinput[i][j][k];
    
    guessinput_shiftrow(dimj, 2, guessshiftsub);
    guessinput_subbytes(dimj, 2, guessshiftsub);
    for(int i = 0; i < 4; i++){
        guessoutput_mix_column(dimj, guessoutput[i], &guessshiftsub[4*i]);
    }
}

// Derive all possible input states in guessinput from the observed input difference in1 ^ in2 and output difference out1 ^ out2.
void guess_input_from_aes_diff(int guessinput[16][2][2], uint8_t in1[16], uint8_t in2[16],
                                        uint8_t out1[16], uint8_t out2[16], const int sboxDDT[256][256][2]){
    for(int i = 0; i < 16; i++)
        for(int j = 0; j < 2; j++)
            for(int k = 0; k < 2; k++)
                guessinput[i][j][k] = -1;
    
    uint8_t din[16], dout[16];
    for(int i = 0; i < 16; i++){
        din[i] = in1[i] ^ in2[i];
        dout[i] = out1[i] ^ out2[i];
    }
    aes_inv_mix_column(dout); aes_inv_shiftrow(dout);
    for(int i = 0; i < 16; i++){
        if(sboxDDT[din[i]][dout[i]][0] == -1){
            printf("\n\nBIG ERROR : din %x dout %x profile incompatible with AES round.\n\n", din[i], dout[i]);
            return;
        }
        guessinput[i][0][0] = sboxDDT[din[i]][dout[i]][0];
        guessinput[i][0][1] = sboxDDT[din[i]][dout[i]][0] ^ din[i];
        if(sboxDDT[din[i]][dout[i]][1] != -1){
            guessinput[i][1][0] = sboxDDT[din[i]][dout[i]][1];
            guessinput[i][1][1] = sboxDDT[din[i]][dout[i]][1] ^ din[i];
        }
    }
    return;
}

// Build guessoutxorin that represents all possibilities resulting on XORing each possibility represented by guessout with each possibility represented by guessin. 
void guess_output_xor_input(int dimj, int guessoutxorin[4][MAX_GUESS][4], const int guessout[4][MAX_GUESSOUTPUT][4], const int guessin[16][dimj][2]){
    int state[4];
    for(int i = 0; i < 4; i++){
        int indexoutxorin = 0;
        int indexin[4][2] = {0};
        do {
            for(int j = 0; j < 4; j++){
                state[j] = guessin[i*4+j][indexin[j][0]][indexin[j][1]];
            }
            int indexout = 0;
            while(indexoutxorin < MAX_GUESS && indexout < MAX_GUESSOUTPUT && guessout[i][indexout][0] != -1) {
                for(int j = 0; j < 4; j++)
                    guessoutxorin[i][indexoutxorin][j] = state[j] ^ guessout[i][indexout][j];
                indexoutxorin++;
                indexout++;
            }
            
        } while(incrementindex(2, indexin, guessin + i*4));
        for(int j = 0; j < 4; j++)
            guessoutxorin[i][indexoutxorin][j] = -1;
    }
}

// Perform a XOR operation on all possibilities represented by guessout with val and store it in guessoutxorconst.
void guess_output_xor_const(int maxlen, int guessoutxorconst[4][maxlen][4], const int guessout[4][maxlen][4], const uint8_t val[16]){
    for(int i = 0; i < 4; i++){
        int j = 0;
        while(j < maxlen && guessout[i][j][0] != -1) {
            for(int k = 0; k < 4; k++)
                guessoutxorconst[i][j][k] = guessout[i][j][k] ^ val[i*4+k];
            j++;
        }
        if(j < maxlen)
            for(int k = 0; k < 4; k++)
                guessoutxorconst[i][j][k] = -1;
    }
}

// Look for a possibility indst of guessin and a possibility outdst of guessout such that indst ^ outdst = res.
void out_in_from_real(int dimj, int indst[16], int outdst[16], const int res[16], const int guessin[16][dimj][2], const int guessout[4][MAX_GUESSOUTPUT][4]){
    bool matchfound;
    for(int col = 0; col < 4; col++){
        int iout = -1;
        matchfound = false;
        while( !matchfound && ++iout < MAX_GUESSOUTPUT && guessout[col][iout][0] != -1){
            for(int i = 0; i < 4; i++){
                int nibble = guessout[col][iout][i] ^ res[col*4+i];
                bool matchbyte = false;
                matchfound = true;
                int j = 0;
                while(!matchbyte && j < dimj && guessin[col*4+i][j][0] != -1){
                    for(int k = 0; k < 2; k++){
                        if(nibble == guessin[col*4+i][j][k]){
                            matchbyte = true;
                            break;
                        }
                    }
                    j++;
                }
                if(!matchbyte){
                    matchfound = false;
                    break;  // go to the next value of guessout.
                }
            }
        }
        if(!matchfound){
            printf("No Match out_in_from_real.\n");
            return;
        }
        for(int i = 0; i < 4; i++){
            outdst[4*col+i] = guessout[col][iout][i];
            indst[4*col+i]  = guessout[col][iout][i] ^ res[4*col+i];
        }
    }
}

// Return the number of column guesses stored in guessoutput.
int getsize_guessoutput (const int guessoutput[MAX_GUESS][4]) {
    int size = -1;
    while(guessoutput[++size][0] != -1);
    return size;
}

// Compare two char arrays.
int cmp_arr_char (const void * a, const void * b, const int len) {
    for(int i = 0; i < len; i++){
        if(((char*) a)[i] != ((char*) b)[i])
            return ((char*) a)[i] - ((char*) b)[i];
    }
    return 0;
}

// Compare two int arrays.
int cmp_arr_int (const void * a, const void * b, const int len) {
    for(int i = 0; i < len; i++){
        if(((int*) a)[i] != ((int*) b)[i])
            return ((int*) a)[i] - ((int*) b)[i];
    }
    return 0;
}

// Compare two guesses of column of guessoutput for sorting.
int cmpguess_col (const void * a, const void * b) {
    return cmp_arr_int(a, b, 4);
}

// Sort all guesses of each column of guessoutput independently in ascending order.
void sort_guess_output(int guessoutput[4][MAX_GUESS][4]){
    for(int i = 0; i < 4; i++){
        qsort(guessoutput[i], getsize_guessoutput(guessoutput[i]), sizeof(int[4]), cmpguess_col);
    }
}

// Check if the quadruple val[4] belongs to an ascending-order sorted array arr of length arr_len.
int is_included_s(const int val[4], const int (*arr)[4], int arr_len){
    int min_index = 0;
    int max_index = arr_len-1;
    int cmp, currindex;
    while(min_index <= max_index){
        currindex = min_index + (max_index - min_index)/2;
        cmp = cmpguess_col(val, arr[currindex]);
        if(cmp == 0)
            return currindex;           // value found, return the index.
        if(cmp < 0)
            max_index = currindex - 1;  // value is lower, look into the low indices.
        else
            min_index = currindex + 1;  // value is higher, look into the high indices.
    }
    return -1;  // value not found.
}

// The meet in the middle procedure as described in the paper. It finds the compatible possibilities among all guesses available and store them in dst.
int meet_in_the_middle_procedure(int dst[3][16], const int guessoutBxorinDxorM11MC02[4][MAX_GUESS][4],
const int guessoutputxorAB[4][MAX_GUESSOUTPUT][4], const int guessinputxorCDxorM01[16][4][2]){

    int guessoutBinDlen[4] = {getsize_guessoutput(guessoutBxorinDxorM11MC02[0]), getsize_guessoutput(guessoutBxorinDxorM11MC02[1]),
    getsize_guessoutput(guessoutBxorinDxorM11MC02[2]), getsize_guessoutput(guessoutBxorinDxorM11MC02[3])};
    int byte_pos[4][4] ={   // positions of the bytes that align to a column after shift row.
        {0,  5,  10, 15},
        {4,  9,  14, 3},
        {8,  13, 2,  7},
        {12, 1,  6,  11}
    };
    
    int xorABstate[16], xorABcol[4];     //  will hold all possible states from the guessoutputxorAB values.
    int xorCDxorM01state[16];           //  will hold all possible states from the guessinputxorCDxorM01 values.
    int currstate[16], currcol[4];      //  will hold all possible states and check inclusion.
    int collision = -1;                 // -1 is no collision found, else it is the index where the collision has been found.

    // Loop over all quadruples forming xorABstate.
    int indexout[4] = {0,0,0,-1};       // this will make the loop start at index { 0 0 0 0 };
    while(iter_guessout(indexout, xorABstate, MAX_GUESSOUTPUT, guessoutputxorAB)){
        
        for(int col = 0; col < 4; col++){
            int inCDcol[4][4][2];
            for(int i = 0; i < 4; i++){
                xorABcol[i] = xorABstate[byte_pos[col][i]];
                for(int j = 0; j < 4; j++)
                    for(int k = 0; k < 2; k++)
                        inCDcol[i][j][k] = guessinputxorCDxorM01[byte_pos[col][i]][j][k];
            }
            int index[4][2] = {0};
            do{
                uint8_t currcol8[4];
                for(int i = 0; i < 4; i++){
                    currcol8[i] = xorABcol[i] ^ inCDcol[i][index[i][0]][index[i][1]];
                    currcol8[i] = aes_sbox[currcol8[i]];
                }
                gmix_column(currcol8);
                for(int i = 0; i < 4; i++)
                    currcol[i] = currcol8[i];
                collision = is_included_s(currcol, guessoutBxorinDxorM11MC02[col], guessoutBinDlen[col]);
            } while(collision == -1 && incrementindex(4, index, inCDcol));
            if(collision == -1){
                break;
            }
            for(int i = 0; i < 4; i++){
                xorCDxorM01state[byte_pos[col][i]] = inCDcol[i][index[i][0]][index[i][1]];
                currstate[col*4+i] = guessoutBxorinDxorM11MC02[col][collision][i];
            }
        }

        if(collision != -1){
            for(int i = 0; i < 16; i++){
                dst[0][i] = currstate[i];   // this holds the correct outBxorinDxorM11MC02
                dst[1][i] = xorABstate[i];   // this holds the correct xorAB
                dst[2][i] = xorCDxorM01state[i];   // this holds the correct xorCDxorM01
            }
            return 1;
        }
    }

    return 0;
}

// The full key-recovery procedure. It takes two message/ciphertex pairs M1/C1 and M2/C2 enciphered with the same nonce, recovers the key and stores it in key. 
void keyrecovery(uint8_t key[32], uint8_t M1[128], uint8_t M2[128], uint8_t C1[128+16], uint8_t C2[128+16], const int sboxDDT[256][256][2]){
    bool verbose = false; // activate the printf of all steps.

    // Compute the key-stream used to encrypt M1 and M2.
    uint8_t MC1[128], MC2[128];
    for(int i = 0; i < 128; i++){
        MC1[i] = M1[i] ^ C1[i];
        MC2[i] = M2[i] ^ C2[i];
    }

    // Collect the many guesses we can infer from the difference profile and work towards the filter.
    int guessinputA[16][2][2];
    guess_input_from_aes_diff(guessinputA, M1+16, M2+16, MC1+48, MC2+48, sboxDDT);
    if(verbose) { printf("Input A:\n"); printguess( 16, 2, guessinputA); }

    int guessinputB[16][2][2];
    guess_input_from_aes_diff(guessinputB, M1+16, M2+16, MC1+64, MC2+64, sboxDDT);
    if(verbose) { printf("\nInput B:\n"); printguess( 16, 2, guessinputB); }

    int guessinputC[16][2][2];
    guess_input_from_aes_diff(guessinputC, M1+48, M2+48, MC1+80, MC2+80, sboxDDT);
    if(verbose) { printf("\nInput C:\n"); printguess( 16, 2, guessinputC); }

    int guessinputD[16][2][2];
    guess_input_from_aes_diff(guessinputD, M1+48, M2+48, MC1+96, MC2+96, sboxDDT);
    if(verbose) { printf("\nInput D:\n"); printguess( 16, 2, guessinputD); }

    // Deduce more branches by XORing the guesses with each other and with constants.
    int guessinputxorAB[16][4][2];
    xor_guess_input(guessinputxorAB, guessinputA, guessinputB);
    if(verbose) { printf("\nA xor B:\n"); printguess( 16, 4, guessinputxorAB);}

    int guessinputxorCD[16][4][2];
    xor_guess_input(guessinputxorCD, guessinputC, guessinputD);
    if(verbose) { printf("\nC xor D:\n"); printguess( 16, 4, guessinputxorCD);}

    int guessinputxorCDxorM01[16][4][2];
    guess_xor_const(16, 4, 2, guessinputxorCDxorM01, guessinputxorCD, M1+32);
    if(verbose) { printf("\nC xor D xor M^0_1:\n"); printguess( 16, 4, guessinputxorCDxorM01);}

    int guessinputDxorM11[16][2][2];
    guess_xor_const(16, 2, 2, guessinputDxorM11, guessinputD, M1+48);
    if(verbose) { printf("\nD xor M^1_1:\n"); printguess( 16, 2, guessinputDxorM11);}

    // From the guesses in input of an AES rounds, deduce the guesses in the output.
    int guessoutputB[4][MAX_GUESSOUTPUT][4];
    guess_output_aes_from_input(2, guessoutputB, guessinputB);
    if(verbose) { printf("\nOutput B:\n"); printguessoutput(MAX_GUESSOUTPUT, guessoutputB);}

    int guessoutputxorAB[4][MAX_GUESSOUTPUT][4];
    guess_output_aes_from_input(4, guessoutputxorAB, guessinputxorAB);
    if(verbose) { printf("\nOutput A xor B:\n"); printguessoutput(MAX_GUESSOUTPUT, guessoutputxorAB);}

    // XOR guesses with each other to deduce all branches between the meet-in-the-middle section.
    int guessoutBxorinDM11[4][MAX_GUESS][4];
    guess_output_xor_input(2, guessoutBxorinDM11, guessoutputB, guessinputDxorM11);
    if(verbose) { printf("\nOutput B xor input DM11:\n"); printguessoutput(MAX_GUESS, guessoutBxorinDM11);}

    int guessoutBxorinDxorM11MC02[4][MAX_GUESS][4];
    guess_output_xor_const(MAX_GUESS, guessoutBxorinDxorM11MC02, guessoutBxorinDM11, MC1+64);
    sort_guess_output(guessoutBxorinDxorM11MC02);
    if(verbose) { printf("\nOutput B xor input D xor M11 xor MC02 sorted:\n"); printguessoutput(MAX_GUESS, guessoutBxorinDxorM11MC02);}

    // Do the meet-in-the-middle procedure to finally filter all guesses into a solution.
    int solutions[3][16];
    if(meet_in_the_middle_procedure(solutions, guessoutBxorinDxorM11MC02, guessoutputxorAB, guessinputxorCDxorM01)==-1){
        printf("meet in the middle FAILURE.\n");
        return;
    }

    // Deduce many states from the meet in the middle result.
    int (*outBxorinDxorM11MC02), (*outputxorAB), (*inputxorCDxorM01);
    outBxorinDxorM11MC02 = solutions[0];
    outputxorAB = solutions[1];
    inputxorCDxorM01 = solutions[2];

    int outBxorinDM11[16];
    for(int i = 0; i < 16; i++)
        outBxorinDM11[i] = outBxorinDxorM11MC02[i] ^ MC1[64+i];
    
    int outB[16], inDM11[16];
    out_in_from_real(2, inDM11, outB, outBxorinDM11, guessinputDxorM11, guessoutputB);

    int inAB[16], inB[16];
    memcpy(inAB, outputxorAB, sizeof(int)*16);
    uint_fun_for_int(16, inAB, aes_inv_oneround);
    memcpy(inB, outB, sizeof(int)*16);
    uint_fun_for_int(16, inB, aes_inv_oneround);

    int inA[16], outA[16],  outAMC11[16];
    for(int i = 0; i < 16; i++)
        inA[i] = inAB[i] ^ inB[i];
    memcpy(outA, inA, sizeof(int)*16);
    uint_fun_for_int(16, outA, aes_oneround);
    for(int i = 0; i < 16; i++)
        outAMC11[i] = outA[i] ^ MC1[48+i];

    int inD[16], S20[16], inC[16],  outC[16];
    for(int i = 0; i < 16; i++){
        inD[i] = inDM11[i] ^ M1[48+i];
        S20[i] = inputxorCDxorM01[i] ^ M1[32+i];
        inC[i] = inD[i] ^ S20[i];
        outC[i] = inC[i];
    }
    uint_fun_for_int(16, outC, aes_oneround);

    // We need the state aroud E to recover the whole internal states.
    uint8_t inE1[16], inE2[16], outE1[16], outE2[16];
    for(int i = 0; i < 16; i++){
        inE1[i] = M1[80+i] ^ M1[64+i];
        inE2[i] = M2[80+i] ^ M2[64+i];
        outE1[i]= MC1[112+i] ^ M1[16+i];
        outE2[i]= MC2[112+i] ^ M2[16+i];
    }
    int guessinputE[16][2][2];
    guess_input_from_aes_diff(guessinputE, inE1, inE2, outE1, outE2, sboxDDT);
    if(verbose) { printf("\nInput E:\n"); printguess( 16, 2, guessinputE); }

    int guessoutputE[4][MAX_GUESSOUTPUT][4];
    guess_output_aes_from_input(2, guessoutputE, guessinputE);
    if(verbose) { printf("\nOutput E:\n"); printguessoutput(MAX_GUESSOUTPUT, guessoutputE);}

    // guess the correct output E (likely 2^16 guesses), recover a whole internal state, verify the guess by computing the tag.
    int indexE[4] = {0,0,0,-1};
    int s_guess[8][16];
    int outE[16], S26[16], S15[16], S11[16], S16[16];
    bool match = false; int T[16]; rocca_state sroccaguess;
    while(!match && iter_guessout(indexE, outE, MAX_GUESSOUTPUT, guessoutputE)){
        for(int i = 0; i < 16; i++){
            S26[i] = outputxorAB[i] ^ inputxorCDxorM01[i] ^ MC1[112+i] ^ outE[i];
            S15[i] = S26[i] ^ inB[i];
        }
        
        uint_fun_for_int(16, S15, aes_inv_oneround);

        for(int i = 0; i < 16; i++)
            S11[i] = S15[i] ^ MC1[32+i];
        uint_fun_for_int(16, S11, aes_inv_oneround);

        for(int i = 0; i < 16; i++)
            S16[i] = S11[i] ^ outC[i] ^ MC1[80+i];

        memcpy(s_guess[0], inAB, sizeof(int)*16);
        memcpy(s_guess[1], S11, sizeof(int)*16);
        memcpy(s_guess[2], outAMC11, sizeof(int)*16);
        memcpy(s_guess[3], inDM11, sizeof(int)*16);
        memcpy(s_guess[4], inB, sizeof(int)*16);
        memcpy(s_guess[5], S15, sizeof(int)*16);
        memcpy(s_guess[6], S16, sizeof(int)*16);
        memcpy(s_guess[7], inputxorCDxorM01, sizeof(int)*16);

        loadroccastate(sroccaguess, s_guess);
        rocca_update(sroccaguess, load_u128(M1+32), load_u128(M1+48));
        rocca_update(sroccaguess, load_u128(M1+64), load_u128(M1+80));
        rocca_update(sroccaguess, load_u128(M1+96), load_u128(M1+112));

        u128_to_arr(T, rocca_mac(sroccaguess, 0, 128));

        match = true;
        for(int i = 0; i < 16; i++){
            match &= (T[i] == C1[128+i]);
        }
    }

    // Invert the encryption to get the initial state and thus the key.
    loadroccastate(sroccaguess, s_guess);
    rocca_downdate(sroccaguess, load_u128(M1+0), load_u128(M1+16));
    for(int i = 0; i < 20; i++){
        rocca_downdate(sroccaguess, load_u128(Z0), load_u128(Z1));
    }

    store_u128(key, sroccaguess[6]);
    store_u128(key+16, sroccaguess[0]);

}

// Test the key recovery procedure and print the time it took to run.
int main(void) {
    clock_t start, end;
    double cpu_time_used;
    start = clock();

    int sboxDDT[256][256][2];   // Given Din and Dout, the input state possibilities are sboxDDT[0]/sboxDDT[0]^Din orelse sboxDDT[1]/sboxDDT[1]^Din.
    initialize_sboxddt(sboxDDT);

    int seed = time(0);
    uint8_t key[32]; randkey(key, seed); // create a random key
    printf("Seed of the key: %u\n", seed);
    uint8_t nonce[16] = {0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,0x10}; // some nonce we will repeat
    uint8_t M1[128];
    uint8_t M2[128];
    for(int i = 0; i<128; i++){
        M1[i] = 0x3f+i;           // Some message value.
        M2[i] = M1[i];
        if(16 <= i && i < 32)
            M2[i] = M1[i] ^ (0x01+i-16);   // Impose a difference on each byte of M+16.
        if(48 <= i && i < 64)
            M2[i] = M1[i] ^ (0x01+i-48);   // Impose a difference on each byte of M+48.
        if(80 <= i && i < 96)
            M2[i] = M1[i] ^ (0x01+i-80);   // Impose a difference on each byte of M+80.
    }

    // Encrypt M1
    uint8_t C1[128+16];
    rocca_seal(C1, 128+16, key, 32, nonce, 16, M1, 128, NULL, 0);

    // Encrypt M2
    uint8_t C2[128+16];
    rocca_seal(C2, 128+16, key, 32, nonce, 16, M2, 128, NULL, 0);

    //The key recovery procedure only has access to the message/ciphertext pairs and recovers the key.
    uint8_t keyguess[32];
    keyrecovery(keyguess, M1, M2, C1, C2, sboxDDT);

    printf("\nKreal : "); printuint8arr(32, key);
    printf("\nKguess: "); printuint8arr(32, keyguess);

    if(cmp_arr_char(key, keyguess, 32) == 0)
        printf("\n*** SUCCESS ***\n");
    else
        printf("\n*** FAILURE ***\n");

    end = clock();
    cpu_time_used = ( (double) (end - start)) / CLOCKS_PER_SEC;
    printf("\nlifetime : %f seconds.\n", cpu_time_used);
}
