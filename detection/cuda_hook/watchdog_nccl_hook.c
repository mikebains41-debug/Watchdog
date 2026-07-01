/*
 * Watchdog AIDR v2.0 - NCCL Gradient Poisoning Detection Hook
 * Intercepts ncclAllReduce during distributed training to detect
 * stochastic gradient inversion and data poisoning attacks.
 *
 * COMPILE:
 *   gcc -shared -fPIC -o libwatchdog_nccl.so watchdog_nccl_hook.c -ldl -lm
 *
 * DEPLOY:
 *   export LD_PRELOAD=./libwatchdog_nccl.so:./libwatchdog_interceptor.so
 *
 * REQUIRES: NCCL installed, multi-GPU host. Test on GPU rental.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <dlfcn.h>
#include <stdint.h>
#include <math.h>
#include <time.h>

/* NCCL types */
typedef void* ncclComm_t;
typedef void* cudaStream_t;
typedef enum {
    ncclInt8=0, ncclUint8=1, ncclInt32=2, ncclUint32=3,
    ncclInt64=4, ncclUint64=5, ncclFloat16=6, ncclFloat32=7,
    ncclFloat64=8, ncclBfloat16=9
} ncclDataType_t;
typedef enum { ncclSum=0, ncclProd=1, ncclMax=2, ncclMin=3 } ncclRedOp_t;

typedef int (*real_ncclAllReduce_t)(
    const void* sendbuff, void* recvbuff, size_t count,
    ncclDataType_t datatype, ncclRedOp_t op,
    ncclComm_t comm, cudaStream_t stream
);

static uint64_t reductions_inspected = 0;
static uint64_t poisoning_events = 0;

#define GRADIENT_VARIANCE_THRESHOLD 500.0
#define GRADIENT_SAMPLE_SIZE 1000

static int verify_gradient_health(const float* buffer, size_t elements) {
    if (!buffer || elements == 0) return 0;

    size_t sample = elements > GRADIENT_SAMPLE_SIZE ? GRADIENT_SAMPLE_SIZE : elements;
    double sum = 0.0, sq_sum = 0.0;

    for (size_t i = 0; i < sample; i++) {
        float val = buffer[i];
        if (isnan(val) || isinf(val)) {
            fprintf(stderr, "[WATCHDOG NCCL] NaN/Inf gradient detected at index %zu — explosive gradient poisoning\n", i);
            return -1;
        }
        sum += val;
        sq_sum += (double)val * val;
    }

    double mean = sum / sample;
    double variance = (sq_sum / sample) - (mean * mean);

    if (variance > GRADIENT_VARIANCE_THRESHOLD) {
        fprintf(stderr, "[WATCHDOG NCCL] Gradient variance %.2f exceeds threshold %.2f — coordinate backdoor suspected\n",
                variance, GRADIENT_VARIANCE_THRESHOLD);
        return -2;
    }
    return 0;
}

int ncclAllReduce(
    const void* sendbuff, void* recvbuff, size_t count,
    ncclDataType_t datatype, ncclRedOp_t op,
    ncclComm_t comm, cudaStream_t stream
) {
    real_ncclAllReduce_t original = (real_ncclAllReduce_t)dlsym(RTLD_NEXT, "ncclAllReduce");
    if (!original) {
        fprintf(stderr, "[WATCHDOG NCCL] CRITICAL: Failed to resolve ncclAllReduce\n");
        exit(EXIT_FAILURE);
    }

    reductions_inspected++;

    if (datatype == ncclFloat32 && sendbuff != NULL) {
        int verdict = verify_gradient_health((const float*)sendbuff, count);
        if (verdict < 0) {
            poisoning_events++;
            fprintf(stderr, "[WATCHDOG NCCL] GRADIENT POISONING BLOCKED — verdict=%d reductions=%lu poisoning_events=%lu\n",
                    verdict, reductions_inspected, poisoning_events);
            return 1;
        }
    }

    return original(sendbuff, recvbuff, count, datatype, op, comm, stream);
}
