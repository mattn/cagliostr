#include <picotest.h>
#undef ok
#define CAGLIOSTR_TEST
#include "cagliostr.hxx"

static void test_cagliostr_insert_record() {
}

static void test_cagliostr_send_records() {
}

int main() {
  subtest("test_cagliostr_insert_record", test_cagliostr_insert_record);
  subtest("test_cagliostr_send_records", test_cagliostr_send_records);
}

