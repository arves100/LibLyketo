/*
	Lyketo CLI Application
*/
#include <stdio.h>

#include <LibLyketo/Config.hpp>
#include <LibLyketo/CryptedObject.hpp>

int main(int argc, char* argv[])
{
	Config cfg;
	CryptedObject obj;
	FILE* fp = nullptr;

	printf("Start read -> %s\n", argv[1]);
	fopen_s(&fp, argv[1], "rb");
	fseek(fp, 0, SEEK_END);
	long fz = ftell(fp);
	rewind(fp);
	uint8_t* b = new uint8_t[fz+1];
	memset(b, 0, fz+1);
	fread(b, sizeof(uint8_t), fz, fp);
	fclose(fp);
	printf("Read ok -> Size %ld\n", fz);

	uint8_t ik[16] = {  0xB9, 0x9E, 0xB0, 0x02, 0x6F, 0x69, 0x81, 0x05, 0x63, 0x98, 0x9B, 0x28, 0x79, 0x18, 0x1A, 0x00 };

	if (!obj.Decrypt(b, fz, (uint32_t*)ik))
	{
		printf("CObj decrypt fail\n");
		return 0;
	}

	printf("Cobj decrypt ok\n");

	printf("Start write -> %s\n", argv[2]);
	fopen_s(&fp, argv[2], "wb");
	fwrite(obj.GetBuffer(), sizeof(uint8_t), obj.GetSize(), fp);
	fclose(fp);
	printf("ok\n");
	return 0;
}
