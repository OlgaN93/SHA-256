/**
 * \file
 * Основной метод
 */

#include <fstream>
#include <iostream>
#include <vector>

#include "SHA_256.h"

using namespace std;

int main()
{
    const char file_name[100] = "D:\\For_Olga\\lern_C++\\projects\\SHA-256\\text_for_hash.txt"; //"pathToFile\\file_name"; 

    FILE *input_for_work_with_file;
    fopen_s(&input_for_work_with_file, file_name, "r");
    cout << sha_256_file(input_for_work_with_file) << endl;

    ifstream input_for_work_with_vector(file_name);
    char sim;
    vector<char> text;

    while (input_for_work_with_vector.get(sim))
    {
        text.push_back(sim);
    }

    cout << sha_256(text) << endl;

    return 0;
}