#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <sys/stat.h>
#include <errno.h>
#include <string.h>

typedef struct {
    bool sev_support;
    bool sev_es_support;
    bool sev_snp_support;

    uint8_t cbitpos;
    uint8_t reduced_phys_bits;
} cpu_caps_t;

void query_cpu_capabilities(cpu_caps_t *res) {
    uint32_t eax, ebx, ecx, edx;

    // query Encrypted Memory Capabilities, see:
    // https://en.wikipedia.org/wiki/CPUID#EAX=8000001Fh:_Encrypted_Memory_Capabilities
    uint32_t query_function = 0x8000001F;
    asm volatile("cpuid"
         : "=a"(eax), "=b"(ebx), "=c"(ecx), "=d"(edx)
         : "0"(query_function)
    );

    res->sev_support = (eax & (1<<1)) != 0;
    res->sev_es_support = (eax & (1<<3)) != 0;
    res->sev_snp_support = (eax & (1<<4)) != 0;

    res->cbitpos = ebx & 0x3f;
    res->reduced_phys_bits = (ebx >> 6) & 0x3f;
}

int main() {
    cpu_caps_t caps;
    query_cpu_capabilities(&caps);

    const char *path = "/run/qemu-server/";
    // Check that the directory exists and create it if it does not.
    struct stat statbuf;
    int ret = stat(path, &statbuf);
    if (ret == 0) {
        if (!S_ISDIR(statbuf.st_mode)) {
            printf("Path %s is not a directory.\n", path);
            return 1;
        }
    } else if (errno == ENOENT) {
        if (mkdir(path, 0755) != 0) {
            printf("Error creating directory %s: %s\n", path, strerror(errno));
            return 1;
        }
    } else {
        printf("Error checking path %s: %s\n", path, strerror(errno));
        return 1;
    }

    FILE *file;
    const char *filename = "/run/qemu-server/host-hw-capabilities.json";
    file = fopen(filename, "w");
    if (file == NULL) {
        perror("Error opening file");
        return 1;
    }

    ret = fprintf(file,
        "{"
        " \"amd-sev\": {"
        " \"cbitpos\": %u,"
        " \"reduced-phys-bits\": %u,"
        " \"sev-support\": %s,"
        " \"sev-support-es\": %s,"
        " \"sev-support-snp\": %s"
        " }"
        " }\n",
        caps.cbitpos,
        caps.reduced_phys_bits,
        caps.sev_support ? "true" : "false",
        caps.sev_es_support ? "true" : "false",
        caps.sev_snp_support ? "true" : "false"
    );
    if (ret < 0) {
        printf("Error writing to file %s: %s\n", path, strerror(errno));
    }

    ret = fclose(file);
    if (ret != 0) {
        printf("Error closing file %s: %s\n", path, strerror(errno));
    }

    return 0;
}
