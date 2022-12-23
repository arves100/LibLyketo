# LibLyketo
A library for messing around with Metin2 file formats.

**NOTICE:** THIS REPOSITORY IS NO LONGER SUPPORTED, ALL DEVELOPERMENT OF LIBLYKETO WAS MOVED INTO https://github.com/OriDevTeam/lyketo.

## Supported file formats
- Protos (MIPT, MIPX, MMPT)
- Crypted Objects (MCOZ and MCSP)
- EterPack (EPKD) with Type 0, 2 and 6

## Features
- Ability to customize the library keys, fourcc and infos.
- Ability to wrap EterPack content file calls from IFileSystem interface.

## Building (with vcpkg)
vcpkg install nlohmann-json spdlog cxxopts snappy lzokay
