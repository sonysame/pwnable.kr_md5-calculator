#include <stdio.h>
#include <stdlib.h>
int main(int argc, char * argv[])
{
	unsigned int v;

	int i;
	int v2[8];
	int r=atoi(argv[1]);
	int v10;
	v=time(0);
	srand(v);
	for(i=0;i<=7;i++){
		v2[i]=rand();
		//printf("%d\n", v2[i]);
	}
	v10=r-v2[4]+v2[6]-v2[7]-v2[2]+v2[3]-v2[1]-v2[5];
	printf("0x%x\n", v10);
	return(v10);
}
