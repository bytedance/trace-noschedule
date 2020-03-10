## Trace-noschedule

在实际问题中，业务经常会遇到延迟高导致的问题。延迟可能来自某个方面。我们的内核默认配成内核态不支持抢占。如果A进程陷入内核态执行时间过长，必然影响其他希望在该核上运行的进程。此时就会导致调度延迟。针对这种case，我们开发了一款工具专门跟踪陷入内核态长时间不调度的进程。这对于我们排查问题可以有一定的指导方向。目前工具已经开发完成，命名为**Trace-noschedule。**

## 如何安装

安装 trace-noschedule 工具很简单，git clone代码后执行如下命令即可安装。

```bash
make -j8
make install
```

## 如何使用

安装trace-noschedule工具成功后。会创建如下 **/proc/trace_noschedule** 目录。

```bash
ls /proc/trace_noschedule
distribution  enable  stack_trace  threshold
```

/proc/trace_noschedule目录下存在 4 个文件，分别：distribution, enable, stack_trace和threshold。工具安装后，默认是关闭状态。

##### 1. 打开tracer

执行以下命令打开tracer。

```bash
echo 1 > /proc/trace_noschedule/enable
```

##### 2. 关闭tracer

执行如下命令关闭tracer。

```bash
echo 0 > /proc/trace_noschedule/enable
```

Note: debug问题后请记得关闭tracer。因为模块内部实现基于sched tracepoint，overhead不能忽略。

##### 3. 设置阈值

trace_noschedule只会针对内核态执行时间超过阈值不调度的进程记录stack trace。为了更高效的运作，我们有必要设定一个合理阈值。例如设置60ms的阈值(单位：ns)：

```bash
echo 60000000 > /proc/trace_noschedule/threshold
```

##### 4. 查看内核态长时间未调度进程执行的时间分布。

```bash
cat /proc/trace_noschedule/distribution

Trace noschedule thread:
     msecs      : count   distribution
    20 -> 39    : 1     |**********                              |
    40 -> 79    : 0     |                                        |
    80 -> 159   : 4     |****************************************|
   160 -> 319   : 2     |********************                    |
```

在内核态有4次执行时间在[80, 159]ms范围内没有调度。

##### 5. 是谁占用CPU不调度

stack_trace记录占用CPU时间超过阈值不调度进程的栈。

```bash
cat /proc/trace_noschedule/stack_trace

 cpu: 0
   COMM: sh PID: 1270013 DURATION: 100ms
   delay_tsc+0x21/0x50
   nosched_test_write+0x53/0x90 [trace_noschedule]
   proc_reg_write+0x36/0x60
   __vfs_write+0x33/0x190
   vfs_write+0xb0/0x190
   ksys_write+0x52/0xc0
   do_syscall_64+0x4f/0xe0
   entry_SYSCALL_64_after_hwframe+0x44/0xa9
```

这是个内核态测试的case，在内核态执行mdelay(100)占用CPU 100ms不调度。此时记录的栈如上面所示。"DURATION"记录的就是执行持续时间。

##### 6. 清除stack trace

如果我们需要清除stack trace记录的信息（stack trace buffer是有大小限制的，必要的时候需要clear）。

```bash
echo 0 > /proc/trace_noschedule/stack_trace
```
