#ifndef HASH_TABLE_H_INCLUDED
#define HASH_TABLE_H_INCLUDED

typedef struct {
    char* key;
    char* value;
} ht_item;

typedef struct {
    int size;
    int base_size;
    int count;
    ht_item** items;
} ht_hash_table;

#define HT_INITIAL_BASE_SIZE 45000
#define HT_PRIME_1 151
#define HT_PRIME_2 163

void ht_insert(ht_hash_table* ht, const char* key, const char* value);
char* ht_search(ht_hash_table* ht, const char* key);
int ht_delete(ht_hash_table* h, const char* key);
static int ht_get_hash(const char* s, const int num_buckets, const int attempt);
void ht_del_hash_table(ht_hash_table* ht);
static int ht_hash(const char* s, const int a, const int m);
static void ht_del_item(ht_item* i);
ht_hash_table* ht_new();
static void ht_resize_down(ht_hash_table* ht);
static void ht_resize_up(ht_hash_table* ht);
static ht_hash_table* ht_new_sized(const int base_size);
static void ht_resize(ht_hash_table* ht, const int base_size);
static ht_item* ht_new_item(const char* k, const char* v);

#endif // HASH_TABLE_H_INCLUDED
