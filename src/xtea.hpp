// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

#pragma once

#include <cstddef>
#include <cstdint>

//namespace core::utils {
    /*
     * Based on the reference implementation.
     * https://en.wikipedia.org/wiki/XTEA
     */
    class XTEA {
       public:
        static void Encrypt(const uint8_t *input, uint8_t *output,
                            std::size_t size, const uint32_t *key,
                            uint32_t numRounds);
        static uint32_t Decrypt(const uint8_t *input, uint8_t *output,
                                std::size_t size, const uint32_t *key,
                                uint32_t numRounds);

       private:
        static void EncryptStep(uint32_t numRounds, uint32_t *v,
                                const uint32_t *key);
        static void DecryptStep(uint32_t numRounds, uint32_t *v,
                                const uint32_t *key);
    };
//}  // namespace core::utils
