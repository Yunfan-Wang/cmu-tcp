#include "cmu_tcp.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#ifdef CP1_TESTING
#include <sys/syscall.h>
 
ssize_t getrandom(void *buf, size_t length, unsigned int flags) {
  const char *value = getenv("CP1_TEST_ISN");
  if (value && length == sizeof(uint32_t)) {
    uint32_t isn = (uint32_t)strtoul(value, NULL, 0);
    memcpy(buf, &isn, length);
    return length;
  }
  return syscall(SYS_getrandom, buf, length, flags);
}
#endif
int main(int argc, char **argv) {
  if (argc != 6) return 2;
  cmu_socket_t s;
  if (cmu_socket(&s, atoi(argv[1]) ? TCP_LISTENER : TCP_INITIATOR,
                 atoi(argv[2]), "127.0.0.1")) return 3;
  unsigned char data[3177];
  FILE *in = fopen(argv[3], "rb");
  if (!in) return 4;
  size_t n;
  while ((n = fread(data, 1, sizeof(data), in)))
    if (cmu_write(&s, data, (int)n)) return 5;
  fclose(in);
  if (cmu_read(&s, NULL, 0, NO_FLAG) != 0 ||
      cmu_write(&s, NULL, 0) != 0 ||
      cmu_write(&s, NULL, -1) != EXIT_ERROR ||
      cmu_read(&s, NULL, -1, NO_WAIT) != EXIT_ERROR) return 6;
      
  FILE *out = fopen(argv[5], "wb");
  if (!out) return 7;

  int left = atoi(argv[4]);
  while (left > 0) {
    int count = cmu_read(&s, data, left < (int)sizeof(data) ? left : (int)sizeof(data), NO_FLAG);
    if (count <= 0) return 8;
    
    if (fwrite(data, 1, count, out) != (size_t)count) return 9;
    left -= count;
  }

  fclose(out);
  puts("RECEIVED");
  fflush(stdout);
  return cmu_close(&s) ? 10 : 0;
}
