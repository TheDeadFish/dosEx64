#include <stdshit.h>
const char progName[] = "test";

static const int peSig[] = {
	0x0eba1f0e, 0xcd09b400, 0x4c01b821, 0x685421cd, 
	0x70207369, 0x72676f72, 0x63206d61, 0x6f6e6e61,
	0x65622074, 0x6e757220, 0x206e6920, 0x20534f44, 
	0x65646f6d, 0x0a0d0d2e, 0x858EE724 };
	
DWORD align_to_boundary(DWORD value, DWORD align)
{
	return (value + (align-1)) & ~(align-1);
}
	
int peFile_AddSect(void* data, const char* section_name, int section_size)
{
	PIMAGE_DOS_HEADER dos_header = (PIMAGE_DOS_HEADER)data; // DOS_HEADER of a mapped file
	PIMAGE_NT_HEADERS nt_headers = (PIMAGE_NT_HEADERS)((DWORD_PTR)dos_header + dos_header->e_lfanew);
	 
	const int name_max_length = 8;
	PIMAGE_SECTION_HEADER last_section = IMAGE_FIRST_SECTION(nt_headers) + (nt_headers->FileHeader.NumberOfSections - 1);
	PIMAGE_SECTION_HEADER new_section = IMAGE_FIRST_SECTION(nt_headers) + (nt_headers->FileHeader.NumberOfSections);
	memset(new_section, 0, sizeof(IMAGE_SECTION_HEADER));
	new_section->Characteristics = IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_CNT_CODE;
	memcpy(new_section->Name, section_name, name_max_length);
	new_section->Misc.VirtualSize = section_size;
	new_section->PointerToRawData = align_to_boundary(last_section->PointerToRawData + last_section->SizeOfRawData,
	nt_headers->OptionalHeader.FileAlignment);
	new_section->SizeOfRawData = align_to_boundary(section_size, nt_headers->OptionalHeader.SectionAlignment);
	new_section->VirtualAddress = align_to_boundary(last_section->VirtualAddress + last_section->Misc.VirtualSize,
	nt_headers->OptionalHeader.SectionAlignment);
	nt_headers->OptionalHeader.SizeOfImage = new_section->VirtualAddress + new_section->Misc.VirtualSize;
	nt_headers->FileHeader.NumberOfSections++;
	
	return new_section->SizeOfRawData;
	
}

extern byte binary_ntvdm_exe_start;
extern byte binary_ntvdm_exe_end;

int main(int argc, char* argv[])
{
	if(argc < 2) {
		printf("dosEx64 <dos exe>\n");
		return -1; }
	
	// get output name
	char* dosExe = argv[1];
	char outName[MAX_PATH];
	strcpy(outName, dosExe);
	strcpy(getExt(outName), "64.exe");
	

	// load windows exe file 
	xarray<byte> file1(&binary_ntvdm_exe_start, 
		&binary_ntvdm_exe_end);
		
	// load windows dos file 	
	auto file2 = loadFile(dosExe);
	if(!file2) { 
		printf("failed to load: %s\n", dosExe);
		return 1; }
		
	// ammend exe header
	memcpy(file1.data+64, peSig, 60);
	RI(file1.data,124) = file1.len;
	int size = peFile_AddSect(file1.data, 
		".dosEx", file2.len);
	
	// write output file
	FILE* fp = fopen(outName, "wb");
	fwrite(file1.data, file1.len, 1, fp);
	fwrite(file2.data, file2.len, 1, fp);
	int extraSize = ftell(fp)+(size-file2.len);
	ftruncate(fileno(fp), extraSize);
	fclose(fp);
}
