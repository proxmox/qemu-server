#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <sys/stat.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>

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
} cpu_caps_amd_sev_t;

typedef struct {
    bool tdx_support;
} cpu_caps_intel_tdx_t;

static inline void cpu_vendor(char vendor[13]) {
    uint32_t eax;
    uint32_t *vp = (uint32_t *)vendor;
    asm volatile("cpuid"
        : "=a"(eax), "=b"(*vp), "=c"(*(vp+2)), "=d"(*(vp+1))
        : "a"(0)
    );
    vendor[12] = '\0';
}

int read_msr(uint32_t msr_index, uint64_t *value) {
    uint64_t data;
    char* msr_file_name = "/dev/cpu/0/msr";
    int fd;

    fd = open(msr_file_name, O_RDONLY);
    if (fd < 0) {
        if (errno == ENXIO) {
            eprintf("rdmsr: No CPU 0\n");
            return -1;
        } else if (errno == EIO) {
            eprintf("rdmsr: CPU doesn't support MSRs\n");
            return -1;
        } else {
            perror("rdmsr: failed to open MSR");
            return -1;
        }
    }

    if (pread(fd, &data, sizeof(data), msr_index) != sizeof(data)) {
        if (errno == EIO) {
            eprintf("rdmsr: CPU cannot read MSR 0x%08x\n", msr_index);
            return -1;
        } else {
            perror("rdmsr: pread");
            return -1;
        }
    }

    *value = data;

    close(fd);
    return 0;
}

void query_cpu_capabilities_sev(cpu_caps_amd_sev_t *res) {
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

int query_cpu_capabilities_tdx(cpu_caps_intel_tdx_t *res) {
    uint64_t tme_value, sgx_value, tdx_value;

    if (read_msr(0x982, &tme_value) == 0 && read_msr(0xa0, &sgx_value) == 0 &&
        read_msr(0x1401, &tdx_value) == 0) {
        res->tdx_support = ((tme_value >> 1) & 1ULL) & (!sgx_value) & ((tdx_value >> 11) & 1ULL);
    } else {
        eprintf("Intel TDX support undetermined\n");
        return -1;
    }
    return 0;
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

    FILE *file = fopen(OUTPUT_PATH, "w");
    if (file == NULL) {
        eprintf("Error opening to file '" OUTPUT_PATH "': %s\n", strerror(errno));
        return 1;
    }

    char vendor[13];
    cpu_vendor(vendor);
    printf("%s\n", vendor);

    int ret = fprintf(file, "{");
    if (ret < 0) {
        eprintf("Error writing to file '" OUTPUT_PATH "': %s\n", strerror(errno));
    }

    if (strncmp(vendor, "AuthenticAMD", 12) == 0) {
        cpu_caps_amd_sev_t caps_sev;
        query_cpu_capabilities_sev(&caps_sev);

        ret = fprintf(file,
            " \"amd-sev\": {"
            " \"cbitpos\": %u,"
            " \"reduced-phys-bits\": %u,"
            " \"sev-support\": %s,"
            " \"sev-support-es\": %s,"
            " \"sev-support-snp\": %s"
            " }",
            caps_sev.cbitpos,
            caps_sev.reduced_phys_bits,
            caps_sev.sev_support ? "true" : "false",
            caps_sev.sev_es_support ? "true" : "false",
            caps_sev.sev_snp_support ? "true" : "false"
        );
        if (ret < 0) {
            eprintf("Error writing to file '" OUTPUT_PATH "': %s\n", strerror(errno));
        }
    } else if (strncmp(vendor, "GenuineIntel", 12) == 0) {
        cpu_caps_intel_tdx_t caps_tdx;
        if (query_cpu_capabilities_tdx(&caps_tdx) == 0) {
            ret = fprintf(file,
                " \"intel-tdx\": {"
                " \"tdx-support\": %s"
                " }",
                caps_tdx.tdx_support ? "true" : "false"
            );
            if (ret < 0) {
                eprintf("Error writing to file '" OUTPUT_PATH "': %s\n", strerror(errno));
            }
        }
    }

    ret = fprintf(file, " }\n");
    if (ret < 0) {
        eprintf("Error writing to file '" OUTPUT_PATH "': %s\n", strerror(errno));
    }

    ret = fclose(file);
    if (ret != 0) {
        eprintf("Error closing file '" OUTPUT_PATH "': %s\n", strerror(errno));
    }

    return 0;
}
