# Toy RC QP via DEVX

This is a toy/example program that uses DEVX and creates an RC QP,
connects it to itself (loopback) and preforms RDMA_WRITE and RDMA_READ.

# Sample output

    $ gcc main.c -o toy -libverbs -lmlx5
    $ sudo ./toy mlx5_2
    Summery:
    IB device: mlx5_2
    RC QPN: 0x1DF
    CQN: 0x485
    PDN: 0x15
    UAR base address: 0x0x7fea4f5af000
    UAR register address: 0x0x7fea4f5af800
    SRC DGID/SGID: fe80::ee0d:9aff:fed4:2e14
    SRC buffer rkey/lkey: 0x7F33
    WRITE buffer rkey/lkey: 0x8333
    READ buffer rkey/lkey: 0x8533
    
    Before RDMA operations:
    Source buffer:
    deadbeef000000000000000000000000000000000000000000000000000000000000
    Write to buffer:
    0000000000000000000000000000000000000000000000000000000000000000
    Read to buffer:
    0000000000000000000000000000000000000000000000000000000000000000
    
    After RDMA_WRITE:
    Source buffer:
    deadbeef000000000000000000000000000000000000000000000000000000000000
    Write to buffer:
    deadbeef000000000000000000000000000000000000000000000000000000000000
    Read to buffer:
    0000000000000000000000000000000000000000000000000000000000000000
    
    After RDMA_READ:
    Source buffer:
    deadbeef000000000000000000000000000000000000000000000000000000000000
    Write to buffer:
    deadbeef000000000000000000000000000000000000000000000000000000000000
    Read to buffer:
    deadbeef000000000000000000000000000000000000000000000000000000000000

We have three buffers at play:

 - Source buffer
 - Write to buffer
 - Read to buffer




1.	Source buffer is filled with 0xdeadbeef at the start of the program.
2.	Preform RDMA_WRITE from **source buffer** to **write to buffer**.
3.	Poll the CQ until we get a completion.
4.	Preform RDMA_READ from **write to buffer** to **read to buffer**.
5.	Poll the CQ until we get a completion.

