#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <sys/stat.h>
#include <errno.h>
#include <string.h>

#define eprintf(...) fprintf(stderr, __VA_ARGS__)

#define OUTPUT_DIR "/run/qemu-server"
#define OUTPUT_FILENAME "host-hw-capabilities.json"
#define OUTPUT_PATH OUTPUT_DIR "/" OUTPUT_FILENAME

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

int prepare_output_directory() {
    // Check that the directory exists and create it if it does not.
    struct stat statbuf;
    int ret = stat(OUTPUT_DIR, &statbuf);
    if (ret == 0) {
        if (!S_ISDIR(statbuf.st_mode)) {
            eprintf("Path '" OUTPUT_DIR "' already exists but is not a directory.\n");
            return 0;
        }
    } else if (errno == ENOENT) {
        if (mkdir(OUTPUT_DIR, 0755) != 0) {
            eprintf("Error creating directory '" OUTPUT_DIR "': %s\n", strerror(errno));
            return 0;
        }
    } else {
        eprintf("Error checking path '" OUTPUT_DIR "': %s\n", strerror(errno));
        return 0;
    }
    return 1;
}

int main() {
    if (!prepare_output_directory()) {
        return 1;
    }

    cpu_caps_t caps;
    query_cpu_capabilities(&caps);

    FILE *file = fopen(OUTPUT_PATH, "w");
    if (file == NULL) {
        eprintf("Error opening to file '" OUTPUT_PATH "': %s\n", strerror(errno));
        return 1;
    }

    int ret = fprintf(file,
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
        eprintf("Error writing to file '" OUTPUT_PATH "': %s\n", strerror(errno));
    }

    ret = fclose(file);
    if (ret != 0) {
        eprintf("Error closing file '" OUTPUT_PATH "': %s\n", strerror(errno));
    }

    return 0;
}
