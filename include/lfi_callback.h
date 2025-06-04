#pragma once

#define LFI_MAXCALLBACKS 4096


#ifdef __cplusplus
extern "C" {
#endif

bool lfi_cbinit(struct LFIContext* ctx);

void* lfi_register_cb(void* fn);

void lfi_unregister_cb(void* fn);

#ifdef __cplusplus
}
#endif
