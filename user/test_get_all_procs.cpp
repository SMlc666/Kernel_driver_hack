#include <unistd.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <algorithm>
#include "driver.hpp"

void print_menu()
{
	printf("\n=== Get All Processes Test Menu ===\n");
	printf("1. List all processes\n");
	printf("2. Search process by name\n");
	printf("3. Search process by PID\n");
	printf("4. Show process count\n");
	printf("5. Exit\n");
	printf("Choice: ");
}

void list_all_processes()
{
	std::vector<c_driver::PROCESS_INFO> processes;

	printf("\n[+] Fetching all processes...\n");
	if (!driver->get_all_processes(processes))
	{
		printf("[-] Failed to get process list\n");
		return;
	}

	printf("[+] Found %zu processes:\n", processes.size());
	printf("\n%-8s %-s\n", "PID", "Name/Path");
	printf("--------------------------------------------------------------------------------\n");

	for (const auto& proc : processes)
	{
		printf("%-8d %s\n", proc.pid, proc.name);
	}

	printf("--------------------------------------------------------------------------------\n");
	printf("Total: %zu processes\n", processes.size());
}

void search_by_name()
{
	std::vector<c_driver::PROCESS_INFO> processes;
	char search_name[256];
	int found_count = 0;

	printf("Enter process name to search: ");
	scanf("%s", search_name);

	printf("\n[+] Fetching all processes...\n");
	if (!driver->get_all_processes(processes))
	{
		printf("[-] Failed to get process list\n");
		return;
	}

	printf("[+] Searching for processes matching '%s'...\n", search_name);
	printf("\n%-8s %-s\n", "PID", "Name/Path");
	printf("--------------------------------------------------------------------------------\n");

	for (const auto& proc : processes)
	{
		if (strstr(proc.name, search_name) != NULL)
		{
			printf("%-8d %s\n", proc.pid, proc.name);
			found_count++;
		}
	}

	printf("--------------------------------------------------------------------------------\n");
	if (found_count == 0)
	{
		printf("No processes found matching '%s'\n", search_name);
	}
	else
	{
		printf("Found %d matching process(es)\n", found_count);
	}
}

void search_by_pid()
{
	std::vector<c_driver::PROCESS_INFO> processes;
	pid_t search_pid;
	bool found = false;

	printf("Enter PID to search: ");
	scanf("%d", &search_pid);

	printf("\n[+] Fetching all processes...\n");
	if (!driver->get_all_processes(processes))
	{
		printf("[-] Failed to get process list\n");
		return;
	}

	printf("[+] Searching for PID %d...\n", search_pid);

	for (const auto& proc : processes)
	{
		if (proc.pid == search_pid)
		{
			printf("\n[+] Process found:\n");
			printf("    PID:       %d\n", proc.pid);
			printf("    Name/Path: %s\n", proc.name);
			found = true;
			break;
		}
	}

	if (!found)
	{
		printf("[-] Process with PID %d not found\n", search_pid);
	}
}

void show_count()
{
	std::vector<c_driver::PROCESS_INFO> processes;

	printf("\n[+] Fetching all processes...\n");
	if (!driver->get_all_processes(processes))
	{
		printf("[-] Failed to get process list\n");
		return;
	}

	printf("[+] Total process count: %zu\n", processes.size());
}

int main(int argc, char const *argv[])
{
	int choice;

	if (!driver->authenticate())
	{
		printf("[-] Driver authentication failed. Is the module loaded?\n");
		return 1;
	}

	printf("[+] Get All Processes Test Client\n");
	printf("[+] Driver device: %s\n", DEVICE_NAME);
	printf("[+] Driver authenticated successfully\n");

	while (1)
	{
		print_menu();
		scanf("%d", &choice);

		switch (choice)
		{
		case 1:
			list_all_processes();
			break;

		case 2:
			search_by_name();
			break;

		case 3:
			search_by_pid();
			break;

		case 4:
			show_count();
			break;

		case 5:
			printf("[+] Exiting...\n");
			return 0;

		default:
			printf("[-] Invalid choice\n");
		}
	}

	return 0;
}
