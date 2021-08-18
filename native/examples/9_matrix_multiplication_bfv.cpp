// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "examples.h"

using namespace std;
using namespace seal;

void bfv_matrix_multiplication_with_parms(SEALContext context)
{
    chrono::high_resolution_clock::time_point time_start, time_end;

    print_parameters(context);
    cout << endl;

    auto &parms = context.first_context_data()->parms();
    auto &plain_modulus = parms.plain_modulus();
    size_t poly_modulus_degree = parms.poly_modulus_degree();

    cout << "Generating secret/public keys: ";
    KeyGenerator keygen(context);
    cout << "Done" << endl;

    auto secret_key = keygen.secret_key();
    PublicKey public_key;
    keygen.create_public_key(public_key);

    RelinKeys relin_keys;
    GaloisKeys gal_keys;
    chrono::microseconds time_diff;
    if (context.using_keyswitching())
    {
        /*
        Generate relinearization keys.
        */
        cout << "Generating relinearization keys: ";
        time_start = chrono::high_resolution_clock::now();
        keygen.create_relin_keys(relin_keys);
        time_end = chrono::high_resolution_clock::now();
        time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
        cout << "Done [" << time_diff.count() << " microseconds]" << endl;

        if (!context.key_context_data()->qualifiers().using_batching)
        {
            cout << "Given encryption parameters do not support batching." << endl;
            return;
        }

        /*
        Generate Galois keys. In larger examples the Galois keys can use a lot of
        memory, which can be a problem in constrained systems. The user should
        try some of the larger runs of the test and observe their effect on the
        memory pool allocation size. The key generation can also take a long time,
        as can be observed from the print-out.
        */
        cout << "Generating Galois keys: ";
        time_start = chrono::high_resolution_clock::now();
        keygen.create_galois_keys(gal_keys);
        time_end = chrono::high_resolution_clock::now();
        time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
        cout << "Done [" << time_diff.count() << " microseconds]" << endl;
    }

    Encryptor encryptor(context, public_key);
    Decryptor decryptor(context, secret_key);
    Evaluator evaluator(context);
    BatchEncoder batch_encoder(context);

    /*
    These will hold the total times used by each operation.
    */
    chrono::microseconds time_batch_sum(0);
    chrono::microseconds time_unbatch_sum(0);
    chrono::microseconds time_encrypt_sum(0);
    chrono::microseconds time_decrypt_sum(0);
    chrono::microseconds time_add_sum(0);
    chrono::microseconds time_multiply_sum(0);
    chrono::microseconds time_multiply_plain_sum(0);
    chrono::microseconds time_square_sum(0);
    chrono::microseconds time_relinearize_sum(0);
    chrono::microseconds time_rotate_rows_one_step_sum(0);
    chrono::microseconds time_rotate_rows_random_sum(0);
    chrono::microseconds time_rotate_columns_sum(0);
    chrono::microseconds time_serialize_sum(0);
#ifdef SEAL_USE_ZLIB
    chrono::microseconds time_serialize_zlib_sum(0);
#endif
#ifdef SEAL_USE_ZSTD
    chrono::microseconds time_serialize_zstd_sum(0);
#endif

    /*
    We can verify that batching is indeed enabled by looking at the encryption
    parameter qualifiers created by SEALContext.
    */
    auto qualifiers = context.first_context_data()->qualifiers();
    cout << "Batching enabled: " << boolalpha << qualifiers.using_batching << endl;

    /*
    The total number of batching `slots' equals the poly_modulus_degree, N, and
    these slots are organized into 2-by-(N/2) matrices that can be encrypted and
    computed on. Each slot contains an integer modulo plain_modulus.
    */
    size_t slot_count = batch_encoder.slot_count();
    size_t row_size = slot_count / 2;
    cout << "Plaintext matrix row size: " << row_size << endl;

    /*
    The matrix plaintext is simply given to BatchEncoder as a flattened vector
    of numbers.
    */
    vector<uint64_t> pod_matrix;
    random_device rd;
    for (size_t i = 0; i < slot_count; i++)
    {
        // pod_matrix.push_back(plain_modulus.reduce(rd()));
        pod_matrix.push_back(2ULL);
    }

    cout << "Input plaintext matrix:" << endl;
    print_matrix(pod_matrix, row_size);

    /*
    First we use BatchEncoder to encode the matrix into a plaintext polynomial.
    */
    Plaintext plain_matrix;
    print_line(__LINE__);
    cout << "Encode plaintext matrix:" << endl;
    batch_encoder.encode(pod_matrix, plain_matrix);

    /*
    We can instantly decode to verify correctness of the encoding. Note that no
    encryption or decryption has yet taken place.
    */
    vector<uint64_t> pod_result;
    cout << "    + Decode plaintext matrix ...... Correct." << endl;
    batch_encoder.decode(plain_matrix, pod_result);
    print_matrix(pod_result, row_size);

    /*
    Next we encrypt the encoded plaintext.
    */
    Ciphertext encrypted_matrix;
    print_line(__LINE__);
    cout << "Encrypt plain_matrix to encrypted_matrix." << endl;
    encryptor.encrypt(plain_matrix, encrypted_matrix);
    cout << "    + Noise budget in encrypted_matrix: " << decryptor.invariant_noise_budget(encrypted_matrix) << " bits"
         << endl;

    /*
    The matrix plaintext is simply given to BatchEncoder as a flattened vector
    of numbers.
    */
    vector<uint64_t> pod_matrix2;
    for (size_t i = 0; i < slot_count; i++)
    {
        // pod_matrix2.push_back(plain_modulus.reduce(rd()));
        pod_matrix2.push_back(2ULL);
    }

    cout << "Input plaintext matrix2:" << endl;
    print_matrix(pod_matrix2, row_size);

    /*
    First we use BatchEncoder to encode the matrix into a plaintext polynomial.
    */
    Plaintext plain_matrix2;
    print_line(__LINE__);
    cout << "Encode plaintext matrix2:" << endl;
    batch_encoder.encode(pod_matrix2, plain_matrix2);

    /*
    We can instantly decode to verify correctness of the encoding. Note that no
    encryption or decryption has yet taken place.
    */
    vector<uint64_t> pod_result2;
    cout << "    + Decode plaintext matrix2 ...... Correct." << endl;
    batch_encoder.decode(plain_matrix2, pod_result2);
    print_matrix(pod_result2, row_size);

    /*
    Next we encrypt the encoded plaintext.
    */
    Ciphertext encrypted_matrix2;
    print_line(__LINE__);
    cout << "Encrypt plain_matrix2 to encrypted_matrix2." << endl;
    encryptor.encrypt(plain_matrix2, encrypted_matrix2);
    cout << "    + Noise budget in encrypted_matrix2: " << decryptor.invariant_noise_budget(encrypted_matrix2)
         << " bits" << endl;

    /*
    We now multiply the second (encrypted) matrix with the encrypted matrix.
    */
    print_line(__LINE__);
    cout << "multiply and relinearize." << endl;
    evaluator.multiply_inplace(encrypted_matrix, encrypted_matrix2);
    evaluator.relinearize_inplace(encrypted_matrix, relin_keys);

    /*
    How much noise budget do we have left?
    */
    cout << "    + Noise budget in result: " << decryptor.invariant_noise_budget(encrypted_matrix) << " bits" << endl;

    /*
    We decrypt and decompose the plaintext to recover the result as a matrix.
    The result is illustrated below

        [ 8, ..., 0 ]
        [ 0, ..., 0 ]

    */
    Plaintext plain_result;
    print_line(__LINE__);
    cout << "Decrypt and decode result." << endl;
    decryptor.decrypt(encrypted_matrix, plain_result);
    batch_encoder.decode(plain_result, pod_result);
    cout << "    + Result plaintext matrix ...... Correct." << endl;
    print_matrix(pod_result, row_size);
}

void bfv_matrix_multiplication()
{
    // 4096 and 8192 works
    size_t poly_modulus_degree = 4096;
    string banner = "BFV Performance Test with Degree: ";
    print_example_banner(banner + to_string(poly_modulus_degree));

    EncryptionParameters parms(scheme_type::bfv);
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(CoeffModulus::BFVDefault(poly_modulus_degree));
    parms.set_plain_modulus(786433);

    bfv_matrix_multiplication_with_parms(parms);
}

/*
Prints a sub-menu to select the performance test.
*/
void test_bfv_matrix_multiplication()
{
    print_example_banner("Computing a Matrix Multiplication");
    cout << "  BFV with a custom degree" << endl;
    bfv_matrix_multiplication();
}
