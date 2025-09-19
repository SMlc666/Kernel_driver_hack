#include <unistd.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include "driver.hpp"

void print_menu()
{
	printf("\n=== Process Hiding Menu ===\n");
	printf("1. Hide process by PID\n");
	printf("2. Unhide process by PID\n");
	printf("3. Clear all hidden processes\n");
	printf("4. Test memory read/write\n");
	printf("5. Exit\n");
	printf("Choice: ");
}

pid_t get_name_pid(char *name)
{
	FILE *fp;
	pid_t pid;
	char cmd[0x100] = "pidof ";

	strcat(cmd, name);
	fp = popen(cmd, "r");
	fscanf(fp, "%d", &pid);
	pclose(fp);
	return pid;
}

int main(int argc, char const *argv[])
{
	int choice;
	pid_t target_pid;
	char process_name[256];

	if (!driver->authenticate())
	{
		printf("[-] Driver authentication failed. Is the module loaded?\n");
		return 1;
	}

	printf("[+] Process Hiding Demo\n");

	printf("[+] Driver device: %s\n", DEVICE_NAME);

	while (1)
	{
		print_menu();
		scanf("%d", &choice);

		switch (choice)
		{
		case 1:
			printf("Enter PID to hide (or process name): ");
			scanf("%s", process_name);
			target_pid = atoi(process_name);
			if (target_pid == 0)
			{
				target_pid = get_name_pid(process_name);
			}
			if (target_pid > 0)
			{
				if (driver->hide_process(target_pid))
				{
					printf("[+] Successfully hid process %d\n", target_pid);
					printf("    Level 1: Process hidden from ps/top/ls /proc\n");
					printf("    Level 2: /proc/%d directory is inaccessible\n", target_pid);
				}
				else
				{
					printf("[-] Failed to hide process %d\n", target_pid);
				}
			}
			else
			{
				printf("[-] Invalid PID or process not found\n");
			}
			break;

		case 2:
			printf("Enter PID to unhide: ");
			scanf("%d", &target_pid);
			if (driver->unhide_process(target_pid))
			{
				printf("[+] Successfully unhid process %d\n", target_pid);
			}
			else
			{
				printf("[-] Failed to unhide process %d\n", target_pid);
			}
			break;

		case 3:
			if (driver->clear_hidden_processes())
			{
				printf("[+] Cleared all hidden processes\n");
			}
			else
			{
				printf("[-] Failed to clear hidden processes\n");
			}
			break;

		case 4:
		{
			printf("Enter process name for memory test: ");
			scanf("%s", process_name);
			pid_t pid = get_name_pid(process_name);
			if (pid > 0)
			{
				driver->initialize(pid);
				printf("Enter module name (e.g., libunity.so): ");
				char module_name[256];
				scanf("%s", module_name);

				uintptr_t base = driver->get_module_base(module_name);
				if (base)
				{
					printf("[+] Module base: 0x%lx\n", base);
					uint64_t value = driver->read<uint64_t>(base);
					printf("[+] Read value: 0x%lx\n", value);
				}
				else
				{
					printf("[-] Module not found\n");
				}
			}
			else
			{
				printf("[-] Process not found\n");
			}
			break;
		}

		case 5:
		{
			printf("Enter process name to get PID: ");
			scanf("%s", process_name);
			target_pid = driver->get_pid(process_name);
			if (target_pid > 0)
			{
				printf("[+] PID of '%s' is %d\n", process_name, target_pid);
			}
			else
			{
				printf("[-] Process '%s' not found\n", process_name);
			}
			break;
		}

		case 6:
			printf("[+] Exiting...\n");
			driver->clear_hidden_processes();
			return 0;

		default:
			printf("[-] Invalid choice\n");
		}
	}

	return 0;
}