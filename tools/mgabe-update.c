#include <ctype.h>
#include <getopt.h>
#include "common.h"
#include "openssl/aes.h"
#include "openssl/sha.h"
#include "openssl/evp.h"
#include "openssl/err.h"
#include "openssl/rand.h"
#include <math.h>
#define DEBUG

/* include code that creates policy by hand */

#define BYTES 4
// size_t attr_len = 0;
// char *attr[MAX_CIPHERTEXT_ATTRIBUTES];
char *attribute_string = NULL, *policy_string = NULL;
Bool abe_update(FENC_SCHEME_TYPE scheme, char *public_params, char *inputfile, char *enc_file, char *ext);
void tokenize_inputfile(char* in, char** abe, char** aes, char** iv);
fenc_attribute_policy *construct_test_policy();

/* Description: mgabe-keygen takes the outfile to write the users keys, and the .
 
 */
int main (int argc, char *argv[]) {
    int aflag,pflag,fflag,oflag;
    char *data = NULL, *enc_file = NULL;
    char *ext = NULL;
    FENC_SCHEME_TYPE mode = FENC_SCHEME_NONE;
    char *public_params = NULL;
    ssize_t data_len;
    FILE *fp;
    int c, exit_status = -1;
    char *file = "input.txt";

    opterr = 0;
    // default
    aflag = pflag = fflag = oflag = FALSE;


    while ((c = getopt (argc, argv, "a:f:p:o:m:h")) != -1) {

        switch (c)
        {
            case 'a': // retrieve attributes from user 
                aflag = TRUE;
                attribute_string = strdup(optarg);
                break;
            case 'f':
                fflag = TRUE;
                file = optarg;
                debug("Encrypted file = '%s'\n", file);
                break;
            case 'p': /* holds policy string */
                pflag = TRUE;
                policy_string = strdup(optarg);
                break;
            case 'o': /* output file */
                oflag = TRUE;
                enc_file = optarg;
                break;
            case 'm':
                if (strcmp(optarg, SCHEME_LSW) == 0) {
                    debug("Encrypting for Lewko-Sahai-Waters KP scheme...\n");
                    mode = FENC_SCHEME_LSW;
                    public_params = PUBLIC_FILE".kp";
                    ext = "kpabe";
                }
                else if(strcmp(optarg, SCHEME_WCP) == 0) {
                    debug("Encrypting for Waters CP scheme...\n");
                    mode = FENC_SCHEME_WATERSCP;
                    public_params = PUBLIC_FILE".cp";
                    ext = "cpabe";
                }
                break;
            case 'h':
                print_help();
                exit(1);
            case '?':
                if (optopt == 'a' || optopt == 'f' || optopt == 'p' || optopt == 'o' || optopt == 'm')
                    fprintf (stderr, "Option -%c requires an argument.\n", optopt);
                else if (isprint (optopt))
                    fprintf (stderr, "Unknown option `-%c'.\n", optopt);
                else
                    fprintf (stderr, "Unknown option character `\\x%x'.\n", optopt);
                return 1;
            default:
                print_help();
                abort ();
        }
}
    if(fflag == FALSE) {
        fprintf(stderr, "Need encrypt file!\n");
        print_help();
        exit(-1);
    }

    if(aflag == FALSE && mode == FENC_SCHEME_LSW) {
        fprintf(stderr, "No attribute list specified!\n");
        print_help();
        goto clean;
    }

    if(pflag == FALSE && mode == FENC_SCHEME_WATERSCP) {
        fprintf(stderr, "No policy specified to encrypt data!\n");
        print_help();
        goto clean;
    }

    if(oflag == FALSE) {
        fprintf(stderr, "Specify file to store ciphertext!\n");
        print_help();
        goto clean;
    }

    if(mode == FENC_SCHEME_NONE) {
        fprintf(stderr, "Please specify a scheme type\n");
        print_help();
        goto clean;
    }

    abe_update(mode, public_params, file, enc_file, ext);
    exit_status = 0;
clean:
    free(data);
    // free attr
    return exit_status;
}

void print_help(void)
{
    printf("Usage: ./abe-update -m [ KP or CP ] -f [ input-filename ]\n\t\t -a Attr1,Attr2,Attr3 -p '((Attr1 and Attr2) or Attr3)' -o [ output-filename ]\n\n");
}

void tokenize_inputfile(char* in, char** abe, char** aes, char** iv)
{
    ssize_t abe_len, aes_len, iv_len;
    char delim[] = ":";
    char *token = strtok(in, delim);
    while (token != NULL) {
        if(strcmp(token, ABE_TOKEN) == 0) {
            token = strtok(NULL, delim);
            abe_len = strlen(token);
            if((*abe = (char *) malloc(abe_len+1)) != NULL) {
                strncpy(*abe, token, abe_len);
            }
        }
        else if(strcmp(token, AES_TOKEN) == 0) {
            token = strtok(NULL, delim);
            aes_len = strlen(token);
            if((*aes = (char *) malloc(aes_len+1)) != NULL) {
                strncpy(*aes, token, aes_len);
            }
        }
        else if(strcmp(token, IV_TOKEN) == 0) {
            token = strtok(NULL, delim);
            iv_len = strlen(token);
            if((*iv = (char *) malloc(iv_len+1)) != NULL) {
                strncpy(*iv, token, iv_len);
            }
        }
        token = strtok(NULL, delim);
    }
}

Bool abe_update(FENC_SCHEME_TYPE scheme, char *public_params, char *inputfile, char *enc_file, char *ext)
{
    FENC_ERROR result;
    fenc_context context;
    fenc_group_params group_params;
    fenc_global_params global_params;
    fenc_ciphertext ciphertext;
    fenc_ciphertext new_ciphertext;
    fenc_function_input func_object_input;
    pairing_t pairing;
    fenc_key secret_key;
    FILE *fp;
    char c;
    size_t pub_len = 0;
    size_t share_s_len = 0;
    size_t serialized_len = 0;
    uint8 public_params_buf[SIZE];
    char session_key[SESSION_KEY_LEN];
    // size_t session_key_len;
    char pol_str[MAX_POLICY_STR];
    int pol_str_len = MAX_POLICY_STR;
    char share_s[SIZE];
    char filename[SIZE];
    /* Clear data structures. */
    memset(&context, 0, sizeof(fenc_context));
    memset(&group_params, 0, sizeof(fenc_group_params));
    memset(&global_params, 0, sizeof(fenc_global_params));	
    memset(&public_params_buf, 0, SIZE);
    memset(&ciphertext, 0, sizeof(fenc_ciphertext));
    memset(&new_ciphertext, 0, sizeof(fenc_ciphertext));
    memset(pol_str, 0, pol_str_len);
    memset(&secret_key, 0, sizeof(fenc_key));

    // all this memory must be free'd 
    char *input_buf = NULL,*keyfile_buf = NULL;
    char *aes_blob64 = NULL, *abe_blob64 = NULL, *iv_blob64 = NULL;
    ssize_t input_len, key_len;

    /* Load user's input file */
    fp = fopen(inputfile, "r");
    if(fp != NULL) {
        if((input_len = read_file(fp, &input_buf)) > 0) {
            // printf("Input file: %s\n", input_buf);
            tokenize_inputfile(input_buf, &abe_blob64, &aes_blob64, &iv_blob64);
            debug("abe ciphertext = '%s'\n", abe_blob64);
            debug("init vector = '%s'\n", iv_blob64);
            debug("aes ciphertext = '%s'\n", aes_blob64);
            free(input_buf);
        }
    }
    else {
        fprintf(stderr, "Could not load input file: %s\n", inputfile);
        return FALSE;
    }
    fclose(fp);

    /* Initialize the library. */
    result = libfenc_init();
    /* Create a Sahai-Waters context. */
    result = libfenc_create_context(&context, scheme);

    /* Load group parameters from a file. */
    fp = fopen(PARAM, "r");
    if (fp != NULL) {
        libfenc_load_group_params_from_file(&group_params, fp);
        libfenc_get_pbc_pairing(&group_params, pairing);
    } else {
        perror("Could not open "PARAM" parameters file.\n");
        return FALSE;
    }
    fclose(fp);

    /* Set up the global parameters. */
    result = context.generate_global_params(&global_params, &group_params);
    report_error("Loading global parameters", result);

    result = libfenc_gen_params(&context, &global_params);
    report_error("Generating scheme parameters and secret key", result);

    debug("Reading the public parameters file = %s\n", public_params);
    /* read file */
    fp = fopen(public_params, "r");
    if(fp != NULL) {
        while (TRUE) {
            c = fgetc(fp);
            if(c != EOF) {
                public_params_buf[pub_len] = c;
                pub_len++;
            }
            else {
                break;
            }
        }
    }
    else {
        perror("File does not exist.\n");
        return FALSE;
    }
    fclose(fp);

    if(scheme == FENC_SCHEME_LSW) {
        fenc_create_func_input_for_attributes(attribute_string, &func_object_input);
        debug_print_attribute_list((fenc_attribute_list*)(func_object_input.scheme_input));
        free(attribute_string);
    }
    else if(scheme == FENC_SCHEME_WATERSCP) {

        printf("wwwwwwwwwwww\n");
        fenc_create_func_input_for_policy(policy_string, &func_object_input);
        debug_print_policy((fenc_attribute_policy *)(func_object_input.scheme_input));
        free(policy_string);
    }
    printf("wwwwwwwwwwww\n");
    /* base-64 decode */
    uint8 *bin_public_buf = NewBase64Decode((const char *) public_params_buf, pub_len, &serialized_len);
    // printf("public params binary = '%s'\n", bin_public_buf);

    /* Import the parameters from binary buffer: */
    result = libfenc_import_public_params(&context, bin_public_buf, serialized_len);
    // report_error("Importing public parameters", result);

    /* key encapsulation to obtain session key from policy */

    size_t abeLength;
    uint8 *data = NewBase64Decode((const char *) abe_blob64, strlen(abe_blob64), &abeLength);
    ciphertext.data = data;
    ciphertext.data_len = abeLength;
    ciphertext.max_len = abeLength;
    printf("------++++++++++-----:%s\n",ciphertext.data);

    result = libfenc_kem_encrypt_update(&context, &func_object_input, &ciphertext, &new_ciphertext);
    //result = libfenc_kem_encryp_update(&context, &func_object_input, SESSION_KEY_LEN, (uint8 *)session_key, &ciphertext, share_s);

    sprintf(filename, "%s.%s", enc_file, ext);
    fp = fopen(filename, "w");

    debug("\tCiphertext stored in '%s'.\n", filename);
    debug("\tABE Ciphertex size is: '%zd'.\n", ciphertext.data_len);
    //debug("\tAES Ciphertext size is: '%d'.\n", data_len);

    /* base-64 both ciphertexts and write to the stdout -- in XML? */
    size_t abe_length, aes_length;
    char *ABE_cipher_base64 = NewBase64Encode(new_ciphertext.data, new_ciphertext.data_len, FALSE, &abe_length);


    /* output ciphertext to disk:  format */
    fprintf(fp, ABE_TOKEN":%s:"ABE_TOKEN_END":", ABE_cipher_base64);
    fprintf(fp, IV_TOKEN":%s:"IV_TOKEN_END":", iv_blob64);
    fprintf(fp, AES_TOKEN":%s:"AES_TOKEN_END, aes_blob64);
    fclose(fp);

    free(aes_blob64);
    free(iv_blob64);
    free(abe_blob64);

    if(ABE_cipher_base64 != NULL)
        free(ABE_cipher_base64);
    //if(iv_base64 != NULL)
        //free(iv_base64);

    fenc_func_input_clear(&func_object_input);

    /* Shutdown the library. */
    result = libfenc_shutdown();
    report_error("Shutting down library", result);
    return TRUE;
}
