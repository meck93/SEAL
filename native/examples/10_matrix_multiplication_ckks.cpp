// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "examples.h"

using namespace std;
using namespace seal;

void ckks_matrix_multiplication_test(SEALContext context)
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
        cout << "Generating relinearization keys: ";
        time_start = chrono::high_resolution_clock::now();
        keygen.create_relin_keys(relin_keys);
        time_end = chrono::high_resolution_clock::now();
        time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
        cout << "Done [" << time_diff.count() << " microseconds]" << endl;

        if (!context.first_context_data()->qualifiers().using_batching)
        {
            cout << "Given encryption parameters do not support batching." << endl;
            return;
        }

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
    CKKSEncoder ckks_encoder(context);

    chrono::microseconds time_encode_sum(0);
    chrono::microseconds time_decode_sum(0);
    chrono::microseconds time_encrypt_sum(0);
    chrono::microseconds time_decrypt_sum(0);
    chrono::microseconds time_addition_sum(0);
    chrono::microseconds time_multiply_sum(0);

    // How many times to run the test?
    long long count = 10;

    // Populate a vector of floating-point values to batch.
    auto slot_count = ckks_encoder.slot_count();
    auto row_size = slot_count / 2;
    cout << "row_size: " << row_size << ", slot_count: " << slot_count << endl;

    vector<double> pod_vector;
    random_device rd;
    for (long i = 0; i < slot_count; i++)
    {
        pod_vector.push_back(double(rd() % 10000));
    }

    cout << "input vector" << endl;
    print_vector(pod_vector);

    // the divisor to get the mean
    Plaintext divisor;
    vector<double> lengths(slot_count, 1.0 / static_cast<double>(slot_count));
    double divisorScale = pow(2.0, 20);
    ckks_encoder.encode(lengths, divisorScale, divisor);

    // to store the decryption
    vector<double> pod_vector2(slot_count);

    cout << "Running tests ";
    for (long long i = 0; i < count; i++)
    {
        /* [Encoding]: for scale we use the square root of the last coeff_modulus prime
        from parms. */
        Plaintext plain(parms.poly_modulus_degree() * parms.coeff_modulus().size(), 0);

        double scale = pow(2.0, 40);
        time_start = chrono::high_resolution_clock::now();
        ckks_encoder.encode(pod_vector, scale, plain);
        time_end = chrono::high_resolution_clock::now();
        time_encode_sum += chrono::duration_cast<chrono::microseconds>(time_end - time_start);

        /* [Encryption] */
        Ciphertext encrypted(context);
        time_start = chrono::high_resolution_clock::now();
        encryptor.encrypt(plain, encrypted);
        time_end = chrono::high_resolution_clock::now();
        time_encrypt_sum += chrono::duration_cast<chrono::microseconds>(time_end - time_start);

        /* [Encrypted Sum] using Rotation */
        vector<Ciphertext> rotations_output(slot_count);
        Ciphertext sum_output;

        time_start = chrono::high_resolution_clock::now();

        for (long steps = 0; steps < slot_count; steps++)
        {
            // shift the vector encrypted #steps to the left
            // store the shifted vector inside rotations_output
            evaluator.rotate_vector(encrypted, steps, gal_keys, rotations_output[steps]);
        }

        // add all rotated vectors inplace
        evaluator.add_many(rotations_output, sum_output);

        time_end = chrono::high_resolution_clock::now();
        time_addition_sum += chrono::duration_cast<chrono::microseconds>(time_end - time_start);

        /* [Division] */
        time_start = chrono::high_resolution_clock::now();

        // divide the vector by its length
        // by multiplying 1 / length
        evaluator.multiply_plain_inplace(sum_output, divisor);
        evaluator.relinearize_inplace(sum_output, relin_keys);

        time_end = chrono::high_resolution_clock::now();
        time_multiply_sum += chrono::duration_cast<chrono::microseconds>(time_end - time_start);

        /* [Decryption] */
        Plaintext plain2(poly_modulus_degree, 0);
        time_start = chrono::high_resolution_clock::now();
        decryptor.decrypt(sum_output, plain2);
        time_end = chrono::high_resolution_clock::now();
        time_decrypt_sum += chrono::duration_cast<chrono::microseconds>(time_end - time_start);

        // [Decoding]
        time_start = chrono::high_resolution_clock::now();
        ckks_encoder.decode(plain2, pod_vector2);
        time_end = chrono::high_resolution_clock::now();
        time_decode_sum += chrono::duration_cast<chrono::microseconds>(time_end - time_start);

        // Print a dot to indicate progress.
        cout << ".";
        cout.flush();
    }

    cout << " Done" << endl << endl;
    cout.flush();

    cout << "decryption" << endl;
    print_vector(pod_vector2);

    auto avg_encode = time_encode_sum.count() / count;
    auto avg_decode = time_decode_sum.count() / count;
    auto avg_encrypt = time_encrypt_sum.count() / count;
    auto avg_decrypt = time_decrypt_sum.count() / count;
    auto avg_addition = time_addition_sum.count() / count;
    auto avg_multiply = time_multiply_sum.count() / count;
    cout << "Average encode: " << avg_encode << " microseconds" << endl;
    cout << "Average decode: " << avg_decode << " microseconds" << endl;
    cout << "Average encrypt: " << avg_encrypt << " microseconds" << endl;
    cout << "Average decrypt: " << avg_decrypt << " microseconds" << endl;
    cout << "Average addition: " << avg_addition << " microseconds" << endl;
    cout << "Average multiply: " << avg_multiply << " microseconds" << endl;
}

void test_ckks_matrix_multiplication_default()
{
    print_example_banner("CKKS Performance Test with Degrees: 4096, 8192, and 16384");

    // It is not recommended to use BFVDefault primes in CKKS. However, for performance
    // test, BFVDefault primes are good enough.
    EncryptionParameters parms(scheme_type::ckks);
    size_t poly_modulus_degree = 4096;
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(CoeffModulus::BFVDefault(poly_modulus_degree));
    ckks_matrix_multiplication_test(parms);

    // cout << endl;
    // poly_modulus_degree = 8192;
    // parms.set_poly_modulus_degree(poly_modulus_degree);
    // parms.set_coeff_modulus(CoeffModulus::BFVDefault(poly_modulus_degree));
    // ckks_matrix_multiplication_test(parms);

    // cout << endl;
    // poly_modulus_degree = 16384;
    // parms.set_poly_modulus_degree(poly_modulus_degree);
    // parms.set_coeff_modulus(CoeffModulus::BFVDefault(poly_modulus_degree));
    // ckks_matrix_multiplication_test(parms);
}

/* Prints a sub-menu to select the performance test. */
void test_ckks_matrix_multiplication()
{
    print_example_banner("CKKS Matrix Multiplication: Performance Test");
    test_ckks_matrix_multiplication_default();
}
