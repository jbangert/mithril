#include <stdio.h>
unsigned long
elf_hash(const unsigned char *name)
{
  unsigned long h = 0, g;
  while (*name)
    {
      h = (h << 4) + *name++;
      if (g = h & 0xf0000000)
        h ^= g >> 24;
      h &= ~g;
    }
  return h;
}
static unsigned int
_dl_elf_hash (const char *name_arg)
{
  const unsigned char *name = (const unsigned char *) name_arg;
  unsigned long int hash = *name;
  if (hash != 0 && name[1] != '\0')
    {
      hash = (hash << 4) + name[1];
      if (name[2] != '\0')
        {
          hash = (hash << 4) + name[2];
          if (name[3] != '\0')
            {
              hash = (hash << 4) + name[3];
              if (name[4] != '\0')
                {
                  hash = (hash << 4) + name[4];
                  name += 5;
                  while (*name != '\0')
                    {
                      unsigned long int hi;
                      hash = (hash << 4) + *name++;
                      hi = hash & 0xf0000000;
    
                      /* The algorithm specified in the ELF ABI is as
                         follows:
    
                         if (hi != 0)
                           hash ^= hi >> 24;
    
                         hash &= ~hi;
    
                         But the following is equivalent and a lot
                         faster, especially on modern processors.  */
    
                      hash ^= hi >> 24;
                    }
    
                  /* Second part of the modified formula.  This
                     operation can be lifted outside the loop.  */
                  hash &= 0x0fffffff;
                }
            }
        }
    }
  return hash;
}
int main(){
  while(!feof(stdin)){
    char buf[1024];
    scanf("%1024s",buf);
    unsigned long ehash1 = elf_hash(buf);
    unsigned long ehash2 = _dl_elf_hash(buf);
    printf("%lu\t %lu \n",ehash1,ehash2);
  }
}
