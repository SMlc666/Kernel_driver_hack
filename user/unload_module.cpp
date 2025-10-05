#include <unistd.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include "driver.hpp"

int main(int argc, char const *argv[])
{
	printf("[+] Kernel Driver Unload Module Test\n");
	printf("[+] Driver device: %s\n", DEVICE_NAME);

	if (!driver->authenticate())
	{
		printf("[-] Driver authentication failed. Is the module loaded?\n");
		return 1;
	}

	printf("[+] Successfully authenticated with driver\n");
	
	printf("[+] Attempting to unload module...\n");
	if (driver->unload_module())
	{
		printf("[+] Module unload request sent successfully\n");
		printf("[+] You can now use 'rmmod my_driver' to unload the module\n");
	}
	else
	{
		printf("[-] Failed to send unload request\n");
		return 1;
	}
	
	printf("[+] Unload test completed successfully\n");
	return 0;
}
