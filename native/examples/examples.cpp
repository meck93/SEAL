// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "examples.h"

using namespace std;
using namespace seal;

int main()
{
    cout << "Microsoft SEAL version: " << SEAL_VERSION << endl;
    while (true)
    {
        cout << "+--------------------------------------------------------------------+" << endl;
        cout << "| The following examples should be executed while reading            |" << endl;
        cout << "| comments in associated files in native/examples/.                  |" << endl;
        cout << "+--------------------------------------------------------------------+" << endl;
        cout << "| Examples                       | Source Files                      |" << endl;
        cout << "+--------------------------------+-----------------------------------+" << endl;
        cout << "| 1. BFV Basics                  | 1_bfv_basics.cpp                  |" << endl;
        cout << "| 2. Encoders                    | 2_encoders.cpp                    |" << endl;
        cout << "| 3. Levels                      | 3_levels.cpp                      |" << endl;
        cout << "| 4. CKKS Basics                 | 4_ckks_basics.cpp                 |" << endl;
        cout << "| 5. Rotation                    | 5_rotation.cpp                    |" << endl;
        cout << "| 6. Serialization               | 6_serialization.cpp               |" << endl;
        cout << "| 7. Performance Test            | 7_performance.cpp                 |" << endl;
        cout << "| 8. Mean/Average Computation    | 8_average_bfv.cpp                 |" << endl;
        cout << "| 9. Matrix Multiplication BFV   | 9_matrix_multiplication_bfv.cpp   |" << endl;
        cout << "| 10. Matrix Multiplication CKKS | 10_matrix_multiplication_ckks.cpp |" << endl;
        cout << "+--------------------------------+-----------------------------------+" << endl;

        /*
        Print how much memory we have allocated from the current memory pool.
        By default the memory pool will be a static global pool and the
        MemoryManager class can be used to change it. Most users should have
        little or no reason to touch the memory allocation system.
        */
        size_t megabytes = MemoryManager::GetPool().alloc_byte_count() >> 20;
        cout << "[" << setw(10) << right << megabytes << " MB] "
             << "Total allocation from the memory pool" << endl;

        int selection = 0;
        bool valid = true;
        do
        {
            cout << endl << "> Run example (1 ~ 10) or exit (0): ";
            if (!(cin >> selection))
            {
                valid = false;
            }
            else if (selection < 0 || selection > 10)
            {
                valid = false;
            }
            else
            {
                valid = true;
            }
            if (!valid)
            {
                cout << "  [Beep~~] valid option: type 0 ~ 10" << endl;
                cin.clear();
                cin.ignore(numeric_limits<streamsize>::max(), '\n');
            }
        } while (!valid);

        switch (selection)
        {
        case 1:
            example_bfv_basics();
            break;

        case 2:
            example_encoders();
            break;

        case 3:
            example_levels();
            break;

        case 4:
            example_ckks_basics();
            break;

        case 5:
            example_rotation();
            break;

        case 6:
            example_serialization();
            break;

        case 7:
            example_performance_test();
            break;

        case 8:
            test_bfv_mean();
            break;

        case 9:
            test_bfv_matrix_multiplication();
            break;

        case 10:
            test_ckks_matrix_multiplication();
            break;

        case 0:
            return 0;
        }
    }

    return 0;
}
