/**
 * \file
 * Реализация алгоритма SHA-256
 */

#include <fstream>
#include <iostream>
#include <vector>
#include <bitset>

#include "SHA_256.h"

using namespace std;

/**
  * Подготавливает полученный текст к виду, подходящему для хеширования
  *
  * \param text Ссылка на вектор, содержащий исходный текст
  *
  * \return Количество блоков
  */
uint32_t text_preparation(vector<char> &text)
{
    uint32_t size_text = size(text);
    uint32_t filling_space = size_text + 1 + RESERVE_BYTE; // учитываем добавочную 1
    uint32_t mod_from_filling = filling_space % WORDS_IN_BLOCK;
    uint32_t cnt_blocks = filling_space / WORDS_IN_BLOCK + bool(mod_from_filling);

    text.push_back(START_FILLING);

    if (mod_from_filling) 
    {
        uint32_t cnt_nulls = WORDS_IN_BLOCK - mod_from_filling;
        text.insert(text.cend(), cnt_nulls, 0b00);
    }
    text.insert(text.cend(), RESERVE_BYTE, 0b00);

    uint32_t size_text_filling = size(text);
    uint32_t cnt_bits_text = size_text * BITS_IN_BYTE;

    for (uint32_t i = size_text_filling - 1, end = size_text_filling - RESERVE_BYTE; i > end; i--)
    {
        text[i] ^= (uint8_t)(cnt_bits_text & 0b11111111);
        cnt_bits_text >>= BITS_IN_BYTE;
    }

    return cnt_blocks;
}

/**
* Объединяет 8-битные элементы в 32-битные
*
* \param *text Указатель на массив из 8-битных элементов
* \param *text_uint_32 Указатель на массив из 32-битных элементов
*/
void conversion_from_8bit_to_32bit(char *text, uint32_t *text_uint_32)
{
    fill(text_uint_32, text_uint_32 + WORDS_IN_BLOCK - 1, 0);

    for (uint32_t i = 0; i < WORDS_IN_BLOCK; i++)
    {
        text_uint_32[i / BYTE_IN_UINT_32_T] <<= BITS_IN_BYTE;
        text_uint_32[i / BYTE_IN_UINT_32_T] ^= text[i];
    }
}

/**
 * Преобразует блоки данных
 *
 * \param *text Указатель на массив из 8-битных элементов
 * \param *hash_values Указатель на массив значений хэша
 * \param *text_uint_32 Указатель на массив из 32-битных элементов
 */
void work_with_block(char *text, uint32_t *hash_values, uint32_t *text_uint_32)
{

    conversion_from_8bit_to_32bit(text, text_uint_32);

    for (uint32_t i = 16; i < WORDS_IN_BLOCK; i++)
    {
        uint32_t s0, s1;
        s0 = _rotr(text_uint_32[i - 15], 7) ^ _rotr(text_uint_32[i - 15], 18) ^ (text_uint_32[i - 15] >> 3);
        s1 = _rotr(text_uint_32[i - 2], 17) ^ _rotr(text_uint_32[i - 2], 19) ^ (text_uint_32[i - 2] >> 10);
        text_uint_32[i] = text_uint_32[i - 16] + s0 + text_uint_32[i - 7] + s1;
    }

    uint32_t a = hash_values[0], b = hash_values[1], c = hash_values[2], d = hash_values[3];
    uint32_t e = hash_values[4], f = hash_values[5], g = hash_values[6], h = hash_values[7];

    for (uint32_t i = 0; i < WORDS_IN_BLOCK; i++)
    {
        uint32_t s0, s1, ch, temp1, temp2, maj;

        s1 = _rotr(e, 6) ^ _rotr(e, 11) ^ _rotr(e, 25);
        ch = (e & f) ^ (~e & g);
        s0 = _rotr(a, 2) ^ _rotr(a, 13) ^ _rotr(a, 22);
        maj = (a & b) ^ (a & c) ^ (b & c);
        temp1 = h + s1 + ch + consts[i] + text_uint_32[i];
        temp2 = s0 + maj;
        h = g;
        g = f;
        f = e;
        e = d + temp1;
        d = c;
        c = b;
        b = a;
        a = temp1 + temp2;
    }

    hash_values[0] += a;
    hash_values[1] += b;
    hash_values[2] += c;
    hash_values[3] += d;
    hash_values[4] += e;
    hash_values[5] += f;
    hash_values[6] += g;
    hash_values[7] += h;
}

/**
 * Реализует алгроитм sha_256 с использованием вектора
 *
 * \param text Вектор, содержащий исходный текст
 *
 * \return Итоговое значение хеша
 */
string sha_256(vector<char> text)
{
    uint32_t hash_values[CNT_HASH_VALUES] = {};

    memcpy(hash_values, HASH_VALUES_CONST, sizeof(HASH_VALUES_CONST));

    uint32_t cnt_blocks = text_preparation(text);

    uint32_t text_uint_32[WORDS_IN_BLOCK] = {};

    for (uint32_t k = 0; k < cnt_blocks; k++)
    {
        char text_ch[WORDS_IN_BLOCK] = {};

        for (uint32_t i = 0; i < WORDS_IN_BLOCK; i++)
        {
            text_ch[i] = text[i + k * WORDS_IN_BLOCK];
        }

        work_with_block(text_ch, hash_values, text_uint_32);
    }

    char hash[WORDS_IN_BLOCK + 1];
    sprintf_s(hash, "%x%x%x%x%x%x%x%x", hash_values[0], hash_values[1], hash_values[2], hash_values[3], hash_values[4], hash_values[5], hash_values[6], hash_values[7]);

    return hash;
}

/**
 * Реализует алгроитм sha_256 с использованием передачи текста из файла частями.
 *
 * \param *input_file указатель на буфер потока, через который передается текст для хеширования
 *
 * \return Итоговое значение хеша
 */
string sha_256_file(FILE *input_file)
{
    uint32_t hash_values[8] = {};

    memcpy(hash_values, HASH_VALUES_CONST, sizeof(HASH_VALUES_CONST));

    uint64_t cnt_sim = 0;
    uint64_t cnt_bits_text = 0;

    char text[WORDS_IN_BLOCK] = {};
    uint32_t text_uint_32[WORDS_IN_BLOCK] = {};

    while (feof(input_file) == 0)
    {
        fill(text, text + sizeof(text), 0);

        cnt_sim = fread_s(text, sizeof(text), sizeof(int8_t), WORDS_IN_BLOCK, input_file);

        cnt_bits_text += cnt_sim * BITS_IN_BYTE;

        if (cnt_sim < WORDS_IN_BLOCK)
        {
            text[cnt_sim] = START_FILLING;

            if (cnt_sim < WORDS_IN_BLOCK - RESERVE_BYTE) // учитываем добавочную единицу
            {
                for (uint32_t i = WORDS_IN_BLOCK - 1, end = WORDS_IN_BLOCK - RESERVE_BYTE; i > end; i--)
                {
                    text[i] ^= cnt_bits_text;
                    cnt_bits_text >>= BITS_IN_BYTE;
                }
            }
        }

        work_with_block(text, hash_values, text_uint_32);
    }

    if (cnt_sim < WORDS_IN_BLOCK && cnt_sim >= WORDS_IN_BLOCK - RESERVE_BYTE)
    {
        fill(text, text + sizeof(text), 0);

        for (uint32_t i = WORDS_IN_BLOCK - 1, end = WORDS_IN_BLOCK - RESERVE_BYTE; i > end; i--)
        {
            text[i] ^= cnt_bits_text;
            cnt_bits_text >>= BITS_IN_BYTE;
        }

        work_with_block(text, hash_values, text_uint_32);
    }

    char hash[WORDS_IN_BLOCK + 1];
    sprintf_s(hash, "%x%x%x%x%x%x%x%x", hash_values[0], hash_values[1], hash_values[2], hash_values[3], hash_values[4], hash_values[5], hash_values[6], hash_values[7]);

    return hash;
}