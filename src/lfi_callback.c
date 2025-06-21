// for the memfd_create definition
#define _GNU_SOURCE
#include <assert.h>
#include <stdint.h>
#include <stdbool.h>
#include <unistd.h>
#include <string.h>
#include <sys/mman.h>

#include "lfi.h"

#include "lfi_callback.h"

extern void lfi_callback();

static void* callbacks[LFI_MAXCALLBACKS];

static ssize_t cbfreeslot()
{
    for (ssize_t i = 0; i < LFI_MAXCALLBACKS; i++) {
        if (!callbacks[i])
            return i;
    }
    return -1;
}

static ssize_t cbfind(void* fn)
{
    for (size_t i = 0; i < LFI_MAXCALLBACKS; i++) {
        if (callbacks[i] == fn)
            return i;
    }
    return -1;
}

#if defined(__x86_64__) || defined(_M_X64)

// Code for a callback trampoline.
static uint8_t cbtrampoline[16] = {
   0x4c, 0x8b, 0x15, 0x09, 0x00, 0x00, 0x00, // mov    0x9(%rip),%r10
   0xff, 0x25, 0x0b, 0x00, 0x00, 0x00,       // jmp    *0xb(%rip)
   0x0f, 0x01f, 0x00,                        // nop
};

struct CallbackEntry {
    uint8_t code[16];
    uint64_t target;
    uint64_t trampoline;
};

static struct CallbackEntry* cbentries_alias;
static struct CallbackEntry* cbentries_box;

bool lfi_cbinit(struct LFIContext* ctx)
{
    int fd = memfd_create("", 0);
    if (fd < 0)
        return false;
    size_t size = LFI_MAXCALLBACKS * sizeof(struct CallbackEntry);
    int r = ftruncate(fd, size);
    if (r < 0)
        goto err;
    // Map callback entries outside the sandbox as read/write.
    void* aliasmap = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (aliasmap == (void*) -1)
        goto err;
    cbentries_alias = (struct CallbackEntry*) aliasmap;
    // Fill in the code for each entry.
    for (size_t i = 0; i < LFI_MAXCALLBACKS; i++) {
        memcpy(&cbentries_alias[i].code, &cbtrampoline[0], sizeof(cbentries_alias[i].code));
    }
    struct HostFile* hf = lfi_host_fdopen(fd);
    assert(hf);
    // Share the mapping inside the sandbox as read/exec.
    lfiptr_t boxmap = lfi_as_mapany(lfi_ctx_as(ctx), size, PROT_READ | PROT_EXEC, MAP_SHARED, hf, 0);
    if (boxmap == (lfiptr_t) -1)
        goto err1;
    cbentries_box = (struct CallbackEntry*) boxmap;
    return true;
err1:
    munmap(aliasmap, size);
err:
    close(fd);
    return false;
}

void* lfi_register_cb(void* fn)
{
    assert(fn);
    assert(cbfind(fn) == -1 && "fn is already registered as a callback");

    ssize_t slot = cbfreeslot();
    if (slot == -1)
        return NULL;

    // write 'fn' into the 'target' field for the chosen slot.
    __atomic_store_n(&cbentries_alias[slot].target, (uint64_t) fn, __ATOMIC_SEQ_CST);
    // write the trampoline into the 'trampoline' field for the chosen slot
    __atomic_store_n(&cbentries_alias[slot].trampoline, (uint64_t) lfi_callback, __ATOMIC_SEQ_CST);

    // Mark the slot as allocated.
    callbacks[slot] = fn;

    return &cbentries_box[slot].code[0];
}

void lfi_unregister_cb(void* fn)
{
    ssize_t slot = cbfind(fn);
    if (slot == -1)
        return;
    callbacks[slot] = NULL;
    __atomic_store_n(&cbentries_alias[slot].target, 0, __ATOMIC_SEQ_CST);
    __atomic_store_n(&cbentries_alias[slot].trampoline, 0, __ATOMIC_SEQ_CST);
}

#elif defined(__aarch64__) || defined(_M_ARM64)

struct CallbackEntry {
    uint32_t code[4];
};

struct CallbackDataEntry {
    uint64_t target;
    uint64_t trampoline;
};

static struct CallbackEntry* cbentries_alias;
static struct CallbackEntry* cbentries_box;

#define LDRLIT(reg, lit) ((0b01011000 << 24) | (((lit) >> 2) << 5) | (reg))

static uint32_t cbtrampoline[4] = {
    LDRLIT(16, LFI_MAXCALLBACKS * sizeof(struct CallbackEntry)), // ldr x16, .+X
    LDRLIT(18, 4 + LFI_MAXCALLBACKS * sizeof(struct CallbackEntry)), // ldr x18, .+X+4
    0xd61f0240, // br x18
    0xd503201f, // nop
};

_Static_assert(sizeof(struct CallbackDataEntry) == sizeof(struct CallbackEntry), "invalid CallbackEntry size");
_Static_assert(LFI_MAXCALLBACKS * sizeof(struct CallbackEntry) % 16384 == 0, "invalid LFI_MAXCALLBACKS");

static struct CallbackDataEntry* dataentries_alias;
static struct CallbackDataEntry* dataentries_box;

static struct CallbackEntry* cbentries_alias;
static struct CallbackEntry* cbentries_box;

bool lfi_cbinit(struct LFIContext* ctx)
{
    int fd = memfd_create("", 0);
    if (fd < 0)
        return false;
    size_t size = 2 * LFI_MAXCALLBACKS * sizeof(struct CallbackEntry);
    int r = ftruncate(fd, size);
    if (r < 0)
        goto err;
    // Map callback entries outside the sandbox as read/write.
    void* aliasmap = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (aliasmap == (void*) -1)
        goto err;
    cbentries_alias = (struct CallbackEntry*) aliasmap;
    dataentries_alias = (struct CallbackDataEntry*) (aliasmap + size / 2);
    // Fill in the code for each entry.
    for (size_t i = 0; i < LFI_MAXCALLBACKS; i++) {
        memcpy(&cbentries_alias[i].code, &cbtrampoline[0], sizeof(cbentries_alias[i].code));
    }
    struct HostFile* hf = lfi_host_fdopen(fd);
    assert(hf);
    // Share the mapping inside the sandbox as read/exec.
    lfiptr_t boxmap = lfi_as_mapany(lfi_ctx_as(ctx), size, PROT_READ, MAP_SHARED, hf, 0);
    if (boxmap == (lfiptr_t) -1)
        goto err1;
    // map the code page as executable
    int ok = lfi_as_mprotect(lfi_ctx_as(ctx), boxmap, size / 2, PROT_READ | PROT_EXEC);
    // TODO: maybe ignore verification failures here since this code region is hand-crafted
    assert(ok == 0);
    cbentries_box = (struct CallbackEntry*) boxmap;
    dataentries_box = (struct CallbackDataEntry*) (boxmap + size / 2);
    return true;
err1:
    munmap(aliasmap, size);
err:
    close(fd);
    return false;
}

void* lfi_register_cb(void* fn)
{
    assert(fn);
    assert(cbfind(fn) == -1 && "fn is already registered as a callback");

    ssize_t slot = cbfreeslot();
    if (slot == -1)
        return NULL;

    // write 'fn' into the 'target' field for the chosen slot.
    __atomic_store_n(&dataentries_alias[slot].target, (uint64_t) fn, __ATOMIC_SEQ_CST);
    // write the trampoline into the 'trampoline' field for the chosen slot
    __atomic_store_n(&dataentries_alias[slot].trampoline, (uint64_t) lfi_callback, __ATOMIC_SEQ_CST);

    // Mark the slot as allocated.
    callbacks[slot] = fn;

    return &cbentries_box[slot].code[0];
}

void lfi_unregister_cb(void* fn)
{
    ssize_t slot = cbfind(fn);
    if (slot == -1)
        return;
    callbacks[slot] = NULL;
    __atomic_store_n(&dataentries_alias[slot].target, 0, __ATOMIC_SEQ_CST);
    __atomic_store_n(&dataentries_alias[slot].trampoline, 0, __ATOMIC_SEQ_CST);
}

#else
#error "Unknown architecture"
#endif
