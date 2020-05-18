// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

#include "xtea.hpp"

#define DELTA 0x9E3779B9

//namespace core::utils {
    void XTEA::Encrypt(const uint8_t *input, uint8_t *output, std::size_t size,
                       const uint32_t *key, uint32_t numRounds) {
        std::size_t steps = size / 8;
        std::size_t currentStep = 0;

        const auto *inp = reinterpret_cast<const uint32_t *>(input);

        std::size_t inputPosition = 0, outputPosition = 0;

        while (currentStep < steps) {
            uint32_t buf[] = {inp[inputPosition], inp[inputPosition+1]};

            EncryptStep(numRounds, buf, key);

            output[outputPosition++] = (buf[0] & 0xFF);
            output[outputPosition++] = ((buf[0] >> 8) & 0xFF);
            output[outputPosition++] = ((buf[0] >> 16) & 0xFF);
            output[outputPosition++] = ((buf[0] >> 24) & 0xFF);

            output[outputPosition++] = (buf[1] & 0xFF);
            output[outputPosition++] = ((buf[1] >> 8) & 0xFF);
            output[outputPosition++] = ((buf[1] >> 16) & 0xFF);
            output[outputPosition++] = ((buf[1] >> 24) & 0xFF);

            currentStep++;
            inputPosition += 2;
        }
    }

    uint32_t XTEA::Decrypt(const uint8_t *input, uint8_t *output,
                           std::size_t size, const uint32_t *key,
                           uint32_t numRounds) {
        std::size_t steps = size / 8;
        std::size_t currentStep = 0;

        const auto *inp = reinterpret_cast<const uint32_t *>(input);

        std::size_t inputPosition = 0, outputPosition = 0;

        while (currentStep < steps) {
            uint32_t buf[] = {inp[inputPosition], inp[inputPosition+1]};

            DecryptStep(numRounds, buf, key);

            output[outputPosition++] = (buf[0] & 0xFF);
            output[outputPosition++] = ((buf[0] >> 8) & 0xFF);
            output[outputPosition++] = ((buf[0] >> 16) & 0xFF);
            output[outputPosition++] = ((buf[0] >> 24) & 0xFF);

            output[outputPosition++] = (buf[1] & 0xFF);
            output[outputPosition++] = ((buf[1] >> 8) & 0xFF);
            output[outputPosition++] = ((buf[1] >> 16) & 0xFF);
            output[outputPosition++] = ((buf[1] >> 24) & 0xFF);

            currentStep++;
            inputPosition += 2;
        }
        
        return static_cast<uint32_t>(outputPosition);
    }

    void XTEA::EncryptStep(uint32_t numRounds, uint32_t *v,
                           const uint32_t *key) {
        uint32_t v0 = v[0], v1 = v[1], sum = 0;
        for (uint32_t i = 0; i < numRounds; i++) {
            v0 += (((v1 << 4) ^ (v1 >> 5)) + v1) ^ (sum + key[sum & 3]);
            sum += DELTA;
            v1 += (((v0 << 4) ^ (v0 >> 5)) + v0) ^ (sum + key[(sum >> 11) & 3]);
        }
        v[0] = v0;
        v[1] = v1;
    }

    void XTEA::DecryptStep(uint32_t numRounds, uint32_t *v,
                           const uint32_t *key) {
        uint32_t v0 = v[0], v1 = v[1];
        uint32_t sum = DELTA * numRounds;
        for (uint32_t i = 0; i < numRounds; i++) {
            v1 -= (((v0 << 4) ^ (v0 >> 5)) + v0) ^ (sum + key[(sum >> 11) & 3]);
            sum -= DELTA;
            v0 -= (((v1 << 4) ^ (v1 >> 5)) + v1) ^ (sum + key[sum & 3]);
        }
        v[0] = v0;
        v[1] = v1;
    }
//}  // namespace core::utils
