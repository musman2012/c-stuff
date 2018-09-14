#include <stdio.h>
#include <string.h>

int shift(int num, int direction, int places)		// direction 1 --> right, -1 --> left
{
	if(direction == 1)
		return (num >> places);
	else if(direction == -1)
		return (num << places);

	return -1;					// direction is not right
}

int main() {
	int IP_SIZE = 0x10;					// 0000 0010
	printf("IP_SIZE after bitwise left is %d\n", shift(IP_SIZE, -1, 2));
	printf("IP_SIZE after bitwise right is %d\n", shift(IP_SIZE, 1, 1));

    	return 0;
}
