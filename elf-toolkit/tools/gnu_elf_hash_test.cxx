#include <stdio.h>
#include  <stdint.h>
uint32_t
dl_new_hash (const char *s)
{
        uint32_t h = 5381;

        for (unsigned char c = *s; c != '\0'; c = *++s)
                h = h * 33 + c;

        return h;
}

int main(){
  while(!feof(stdin)){
    char buf[1024];
    scanf("%1024s",buf);
    unsigned long ehash1 = dl_new_hash(buf);
    printf("%lu \n",ehash1);
  }
}

