//+build ignore

#include <linux/sched.h>

#include <linux/bpf.h>

#include <bpf/bpf_helpers.h>

#include <bpf/bpf_tracing.h>

#include <stddef.h>

#ifndef TASK_COMM_LEN
#define TASK_COMM_LEN 16
#endif

struct key_t {
  __u32 pid;
};

struct val_t {
  __u64 start_time;
  __u64 elapsed_time;
};

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __type(key, struct key_t);
  __type(value, struct val_t);
  __uint(max_entries, 10240);
} process_time_map SEC(".maps");

// this is the structure of the sched_switch event
struct sched_switch_args {
  char prev_comm[TASK_COMM_LEN];
  int prev_pid;
  int prev_prio;
  long prev_state;
  char next_comm[TASK_COMM_LEN];
  int next_pid;
  int next_prio;
};

SEC("tracepoint/sched/sched_switch")
int cpu_processing_time(struct sched_switch_args *ctx) {
  // get the current time in ns
  __u64 ts = bpf_ktime_get_ns();

  // we need to check if the process is in our map
  struct key_t prev_key = {
      .pid = ctx->prev_pid,
  };
  struct val_t *val = bpf_map_lookup_elem(&process_time_map, &prev_key);

  // if the previous PID does not exist it means that we just started
  // watching or we missed the start somehow
  // so we ignore it for now
  if (val) {
    // Calculate and store the elapsed time for the process and we reset the
    // start time so we can measure the next cycle of that process
    __u64 elapsed_time = ts - val->start_time;
    struct val_t new_val = {.start_time = ts, .elapsed_time = elapsed_time};
    bpf_map_update_elem(&process_time_map, &prev_key, &new_val, BPF_ANY);
    return 0;
  };

  // we need to check if the next process is in our map
  // if its not we need to set initial time
  struct key_t next_key = {
      .pid = ctx->next_pid,
  };
  struct val_t *next_val = bpf_map_lookup_elem(&process_time_map, &prev_key);
  if (!next_val) {
    struct val_t next_new_val = {.start_time = ts};
    bpf_map_update_elem(&process_time_map, &next_key, &next_new_val, BPF_ANY);
    return 0;
  }

  return 0;
}

char _license[] SEC("license") = "Dual MIT/GPL";
