# Watchdog AIDR - CUDA/NCCL Interception Hooks

## Files

- `watchdog_hook.c` — Intercepts `cudaLaunchKernel` before hardware execution
- `watchdog_nccl_hook.c` — Intercepts `ncclAllReduce` for gradient poisoning detection

## Compile

```bash
# CUDA hook
gcc -shared -fPIC -o libwatchdog_interceptor.so watchdog_hook.c -ldl

# NCCL hook  
gcc -shared -fPIC -o libwatchdog_nccl.so watchdog_nccl_hook.c -ldl -lm
export LD_PRELOAD=./libwatchdog_interceptor.so:./libwatchdog_nccl.so
python3 your_inference_script.py



