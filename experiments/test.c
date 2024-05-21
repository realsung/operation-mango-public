//gcc test.c
//strip a.out
//mv a.out a.out.strip
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>


void* id(void *parameter) {
  return parameter;
}


char *sangjun2()
{
  for(int i=0;i<10;i++)
    printf("%d\n",i);
  char a[0x100];
  memset(a,0x41,0x100);
  return a;
}

void a() {
  //char parameter[0x100];
  //read(0,parameter,0x100);
  char *parameter;
  parameter=sangjun2();
  id(parameter);
  b(parameter);
}


void b(void *parameter) {
  id(parameter);
  c(parameter);
}


void c(void *parameter) {
  id(parameter);
  d(parameter);
}


void d(void *parameter) {
  id(parameter);
  system(parameter);
}


int main(int argc, char *argv[]) {
  puts("***** a *****");
  //a(argv[1]);
  a();

  return 0;
}
