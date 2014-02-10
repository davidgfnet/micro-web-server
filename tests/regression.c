

#include "server_config.h"
#include "server.h"

const char * test1[] = {"123-456", "12345678901234-12345678901234", "123-", "123", "123--", "123--456",
			"-1111", "-", "123456789-1234-111111", " bytes = 1111-2222 " };

const char * test2_1[] = {"/home/user", "/home//user", "/home/user/path/../", "/h/u/", "/h/u/",
			"/h/u/", "/h/u/", "/h/u/", "/h/u/", "/h/u/" };
			
const char * test2_2[] = {"//path1///path2/path3/../path4/../../../path5/file.htm",
			"//path1///path2/path3/../path4/../../../../../../path5/file.htm",
			"//path1///path2/path3/../path4/../path5/file.htm",
			"/../../path4/../../../path5/file.htm",
			"//////file.htm",
			"../../path1/path2/test.htm",
			"../../path1/test.htm",
			"..///////..////path1/path2/",
			"..///////..////path1/p%20ath2/",
			"..///////..////path1/p+ath2/"
			};

const char * test3[] = {"%45%46%47%48%49%50%51%52%53%54",
			"%%45%46%47%48%49%50%51%52%53%54",
			"%4a%46%47%48%49%50%51%52%53%54",
			"%4A%46%47%48%49%50%51%52%53%54",
			"%%%%",
			"%C3%A1%C3%A9%C3%AD%C3%B3%C3%BA%C3%A0%C3%A8%C3%AC%C3%B2%C3%B9abcd-!%22%23%40",
			"%a%b%1%2",
			"%%a%%b%%1%%2",
			"%%%45%46%%47",
			"%"
			};

int main() {
	int i,j;
	
	// Test range parser:
	long long start, end;
	int r;
	for (i = 0; i < 10; i++) {
		r = parse_range_req(test1[i], &start, &end);
		printf("%d %lld %lld\n", r, start, end);
	}

	// Test path creation
	for (i = 0; i < 10; i++) {
		char temp[4096];
		path_create(test2_1[i], test2_2[i], temp);
		printf("%s\n", temp);
	}
	
	// Test urldecode
	for (i = 0; i < 10; i++) {
		char temp[4096];
		urldecode (temp, test3[i]);
		printf("%s\n", temp);
	}
	
	// Fuzz test!
	for (i = 0; i < 1000000; i++) {
		char temp[4096], temp2[4096], temp4[4096*2];;
		for (j = 0; j < 4096; j++) {
			temp[j]  = rand();
			temp2[j] = rand();
		}
		temp[4095]  = 0;
		temp2[4095] = 0;
		parse_range_req(temp, &start, &end);
		path_create(temp, temp2, temp4);
		urldecode(temp4, temp);
		
		if (i%100000 == 0)
			printf("Progress: %d %%\n", i / 10000);
	}

	// ASCII targeted fuzz test!
	const char dict[] = "1234567890-/ACBDEFGabcdefg%!\"·$/()=.";
	int tt = strlen(dict);
	for (i = 0; i < 1000000; i++) {
		char temp[4096], temp2[4096], temp4[4096*2];;
		for (j = 0; j < 4096; j++) {
			temp[j]  = dict[rand() % tt];
			temp2[j] = dict[rand() % tt];
		}
		temp[4095]  = 0;
		temp2[4095] = 0;
		parse_range_req(temp, &start, &end);
		path_create(temp, temp2, temp4);
		urldecode(temp4, temp);
		
		if (i%100000 == 0)
			printf("Progress: %d %%\n", i / 10000);
	}

}

