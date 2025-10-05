#include <unistd.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include "driver.hpp"

void print_menu()
{
	printf("\n=== Memory Segments Test Menu ===\n");
	printf("1. List all memory segments by PID\n");
	printf("2. List all memory segments by process name\n");
	printf("3. Search segments by path/name\n");
	printf("4. Show segment statistics\n");
	printf("5. Exit\n");
	printf("Choice: ");
}

const char* get_perm_string(unsigned long flags)
{
	static char perm[5];
	perm[0] = (flags & 0x01) ? 'r' : '-';  // VM_READ
	perm[1] = (flags & 0x02) ? 'w' : '-';  // VM_WRITE
	perm[2] = (flags & 0x04) ? 'x' : '-';  // VM_EXEC
	perm[3] = (flags & 0x08) ? 's' : 'p';  // VM_SHARED
	perm[4] = '\0';
	return perm;
}

void list_memory_segments(pid_t pid)
{
	std::vector<c_driver::MEM_SEGMENT_INFO> segments;

	printf("\n[+] Fetching memory segments for PID %d...\n", pid);
	driver->set_target_pid(pid);

	if (!driver->get_memory_segments(segments))
	{
		printf("[-] Failed to get memory segments\n");
		return;
	}

	printf("[+] Found %zu memory segments:\n\n", segments.size());
	printf("%-18s %-18s %-10s %-6s %s\n", "Start", "End", "Size", "Perms", "Path");
	printf("--------------------------------------------------------------------------------------------\n");

	for (const auto& seg : segments)
	{
		size_t size = seg.end - seg.start;
		const char* path = seg.path[0] ? seg.path : "[anon]";

		printf("0x%016lx 0x%016lx %10zu %s %s\n",
			seg.start, seg.end, size, get_perm_string(seg.flags), path);
	}

	printf("--------------------------------------------------------------------------------------------\n");
	printf("Total segments: %zu\n", segments.size());
}

void list_by_process_name()
{
	char process_name[256];
	printf("Enter process name: ");
	scanf("%s", process_name);

	pid_t pid = driver->get_pid(process_name);
	if (pid <= 0)
	{
		printf("[-] Process '%s' not found\n", process_name);
		return;
	}

	printf("[+] Found process '%s' with PID %d\n", process_name, pid);
	list_memory_segments(pid);
}

void search_segments_by_path()
{
	pid_t pid;
	char search_path[256];

	printf("Enter PID: ");
	scanf("%d", &pid);

	printf("Enter path to search (e.g., .so, .apk, libc): ");
	scanf("%s", search_path);

	std::vector<c_driver::MEM_SEGMENT_INFO> segments;
	driver->set_target_pid(pid);

	printf("\n[+] Fetching memory segments for PID %d...\n", pid);
	if (!driver->get_memory_segments(segments))
	{
		printf("[-] Failed to get memory segments\n");
		return;
	}

	printf("[+] Searching for segments containing '%s'...\n\n", search_path);
	printf("%-18s %-18s %-10s %-6s %s\n", "Start", "End", "Size", "Perms", "Path");
	printf("--------------------------------------------------------------------------------------------\n");

	int found_count = 0;
	for (const auto& seg : segments)
	{
		if (seg.path[0] && strstr(seg.path, search_path) != NULL)
		{
			size_t size = seg.end - seg.start;
			printf("0x%016lx 0x%016lx %10zu %s %s\n",
				seg.start, seg.end, size, get_perm_string(seg.flags), seg.path);
			found_count++;
		}
	}

	printf("--------------------------------------------------------------------------------------------\n");
	if (found_count == 0)
	{
		printf("No segments found matching '%s'\n", search_path);
	}
	else
	{
		printf("Found %d matching segment(s)\n", found_count);
	}
}

void show_statistics()
{
	pid_t pid;
	printf("Enter PID: ");
	scanf("%d", &pid);

	std::vector<c_driver::MEM_SEGMENT_INFO> segments;
	driver->set_target_pid(pid);

	printf("\n[+] Fetching memory segments for PID %d...\n", pid);
	if (!driver->get_memory_segments(segments))
	{
		printf("[-] Failed to get memory segments\n");
		return;
	}

	size_t total_size = 0;
	size_t executable_count = 0;
	size_t writable_count = 0;
	size_t readable_count = 0;
	size_t anon_count = 0;
	size_t file_count = 0;

	for (const auto& seg : segments)
	{
		size_t size = seg.end - seg.start;
		total_size += size;

		if (seg.flags & 0x04) executable_count++;  // VM_EXEC
		if (seg.flags & 0x02) writable_count++;    // VM_WRITE
		if (seg.flags & 0x01) readable_count++;    // VM_READ

		if (seg.path[0])
			file_count++;
		else
			anon_count++;
	}

	printf("\n=== Memory Segment Statistics for PID %d ===\n", pid);
	printf("Total segments:      %zu\n", segments.size());
	printf("Total memory:        %zu bytes (%.2f MB)\n", total_size, total_size / (1024.0 * 1024.0));
	printf("\nPermission breakdown:\n");
	printf("  Readable:          %zu\n", readable_count);
	printf("  Writable:          %zu\n", writable_count);
	printf("  Executable:        %zu\n", executable_count);
	printf("\nType breakdown:\n");
	printf("  File-backed:       %zu\n", file_count);
	printf("  Anonymous:         %zu\n", anon_count);
}

int main(int argc, char const *argv[])
{
	int choice;

	if (!driver->authenticate())
	{
		printf("[-] Driver authentication failed. Is the module loaded?\n");
		return 1;
	}

	printf("[+] Memory Segments Test Client\n");
	printf("[+] Driver device: %s\n", DEVICE_NAME);
	printf("[+] Driver authenticated successfully\n");

	while (1)
	{
		print_menu();
		scanf("%d", &choice);

		switch (choice)
		{
		case 1:
		{
			pid_t pid;
			printf("Enter PID: ");
			scanf("%d", &pid);
			list_memory_segments(pid);
			break;
		}

		case 2:
			list_by_process_name();
			break;

		case 3:
			search_segments_by_path();
			break;

		case 4:
			show_statistics();
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
