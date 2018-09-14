#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "hash_table.h"

int main() {
    int IP_SIZE = 20, r;
    char *ip = "12.1.1.1"; char ms_num[IP_SIZE];
    ht_hash_table* ht = ht_new();		// creating new hash
    FILE *f1 = fopen("IPS", "r");
    FILE *f2 = fopen("VIPS", "r");
    printf("fgets going to be called.......\n");

    clock_t start, end, new_start, new_end, total_time, new_total_time;
    double cpu_time_used, cpu_time_used_new;
//    ht_hash_table* ht = ht_new();
//        start = clock();
    
//    fgets(buff, IP_SIZE, f);
//
    start = clock();
    int i_start = start; int temp = 0;

//    start = start + 1000000;

///    printf("Start time:=====>>>> %d\n", start);
    while ((r = fscanf(f2, "%s\n", ms_num)) != EOF) {

   // 	while ((r = fscanf(f1, "%s\n", ip)) != EOF) {
    //		printf("String read: %s\n", ip);
		ht_insert(ht, ms_num, ip);              // (hash_table, key, value)a
		// in case of second table, we'll call this function in this manner ht_insert(ht, ip, "1");
   // 	} 	
/**
    	if (temp % 10000 == 0) {
		end = clock();
		printf("End time: %d\n", end);
//		start = end;
	}
	temp++;
*/
    }
//    int i_end = end;
//    printf("End time: %d\n", end);

//    printf("String read: %s\n", buff);
//    fclose(f);


//    clock_t start, end;
 //   double cpu_time_used;
//    ht_hash_table* ht = ht_new();
//    end = clock();
/*
    for (int i = 0; i < 250; i++) {
    char ip [ 20 ];  // Longest possible IP address is 20 bytes)
    sprintf ( ip, "%d.%d.%d.%d", rand() & 0xFF, rand() & 0xFF,
                              rand() & 0xFF, rand() & 0xFF ) ;
    ht_insert(ht, ip, ip);		// (hash_table, key, value)
    }
*/
//    end = clock();
//    cpu_time_used = end - start;

//    printf("CLOCK/SEC : %d\n", CLOCKS_PER_SEC);

//    total_time = ((double) 1.0*(i_end - i_start));  // CLOCKS_PER_SEC;

//    cpu_time_used = cpu_time_used/CLOCKS_PER_SEC;

//    printf("Insertion time for all insertions ======= is %f miliseconds.\n", total_time);

    new_start = clock();

    printf("New Start time--->: %d\n", new_start);
    char * item = NULL;

    for(int i = 0; i < 10000; i++) {    
    	item = ht_search(ht,"971506630944");		// (hash_table, key)
    }

//    new_end = clock();

//    printf("New end time: %d\n", new_end);

//    cpu_time_used_new = ((double) (new_end - new_start)) / CLOCKS_PER_SEC;

//    printf("Time for searching is %d miliseconds.\n", cpu_time_used_new);
    if (item == NULL) {					// no default value is set, NULL implies that there is no IP against this MSIDN number
        printf("Item not found\n");
      }
    else {
      printf("Value: %s\n",item);
    }

    printf("Deletion has returned %d.\n", ht_delete(ht, "971509992473"));

    new_end = clock();

    printf("New end time: %d\n", new_end);

    fclose(f1);
    fclose(f2);

    return 0;
}
