// SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB
/*
 * Copyright (c) 2019, Mellanox Technologies inc.  All rights reserved.
 */

#include <stdlib.h>
#include <unistd.h>
#include <limits.h>
#include <malloc.h>

#include <arpa/inet.h>
#include <infiniband/verbs.h>
#include <infiniband/mlx5dv.h>

#include "devx_prm.h"

#define QUEUE_SIZE 128
#define SG_LIST_SIZE 1
#define SINGLE_BUF_SIZE 64

#define max(a, b) \
        ({ \
                typeof(a) _a = (a); \
                typeof(b) _b = (b); \
                _a > _b ? _a : _b; \
        })

#define max_t(t, a, b) \
        ({ \
                t _ta = (a); \
                t _tb = (b); \
                max(_ta, _tb); \
        })

#define likely(x) __builtin_expect(!!(x), 1)

#define unlikely(x) __builtin_expect(!!(x), 0)

struct dr_qp_init_attr {
	struct dr_cq *cq;
	uint32_t pdn;
	struct mlx5dv_devx_uar *uar;
	struct ibv_qp_cap cap;
	enum ibv_qp_type qp_type;
};

enum dr_roce_version {
	MLX5_ROCE_VERSION_1 = 0,
	MLX5_ROCE_VERSION_2 = 2,
};

enum {
	DR_CQ_SET_CI = 0,
	DR_CQ_ARM_DB = 1,
};

struct dr_gid_attr {
	union ibv_gid gid;
	enum dr_roce_version roce_ver;
	uint8_t mac[6];
};

struct dr_qp_rtr_attr {
	struct dr_gid_attr dgid_attr;
	enum ibv_mtu mtu;
	uint16_t qp_num;
	uint16_t port_num;
	uint32_t rq_psn;
	uint8_t min_rnr_timer;
	uint8_t	sgid_index;
};

struct dr_qp_rts_attr {
	uint8_t timeout;
	uint8_t	retry_cnt;
	uint8_t	rnr_retry;
	uint32_t sq_psn;
};

struct dr_mr {
	struct mlx5dv_devx_umem *buf_umem;
	struct mlx5dv_devx_obj *obj;
	uint8_t *buf;
	size_t size;
	uint32_t id;
};

struct dr_pd {
	struct mlx5dv_devx_obj *obj;
	uint32_t id;
};

struct dr_wq {
	unsigned *wqe_head;
	unsigned wqe_cnt;
	unsigned max_post;
	unsigned head;
	unsigned tail;
	unsigned cur_post;
	int max_gs;
	int wqe_shift;
	int offset;
	void *qend;
};

struct dr_buf {
	void *buf;
	size_t length;
	int base;
};

struct dr_qp {
	struct dr_buf buf;
	struct dr_wq sq;
	struct dr_wq rq;
	int sq_size;
	void *sq_start;
	int max_inline_data;
	__be32 *db;
	struct mlx5dv_devx_uar *uar;
	struct mlx5dv_devx_umem *buf_umem;
	struct mlx5dv_devx_umem *db_umem;
	uint32_t id;
	struct mlx5dv_devx_obj *obj;
};

struct dr_cq {
	uint8_t *buf;
	uint32_t cons_index;
	int ncqe;
	struct dr_qp *qp; /* Assume CQ per QP */
	__be32 *db;
	struct mlx5dv_devx_obj *obj;
	struct mlx5dv_devx_uar *uar;
	struct mlx5dv_devx_umem *buf_umem;
	struct mlx5dv_devx_umem *db_umem;
	uint32_t id;
};

struct global_ctx {
	struct ibv_context *ctx;
	struct mlx5dv_devx_uar *uar;
	struct dr_pd *dr_pd;
	struct dr_cq *dr_cq;
	struct dr_mr *dr_mr_src;
	struct dr_mr *dr_mr_write;
	struct dr_mr *dr_mr_read;
	struct dr_qp *dr_qp;
};

static inline int dr_ilog2(int n)
{
	int t;

	if (n <= 0)
		return -1;

	t = 0;
	while ((1 << t) < n)
		++t;

	return t;
}

static inline unsigned long align(unsigned long val, unsigned long align)
{
	return (val + align - 1) & ~(align - 1);
}

static inline unsigned DIV_ROUND_UP(unsigned n, unsigned d)
{
	return (n + d - 1u) / d;
}

static int dr_query_gid(struct ibv_context *ctx, uint16_t index,
			uint8_t vhca_port_num, struct dr_gid_attr *attr)
{
	uint32_t out[DEVX_ST_SZ_DW(query_roce_address_out)] = {0};
	uint32_t in[DEVX_ST_SZ_DW(query_roce_address_in)] = {0};
	int ret;

	DEVX_SET(query_roce_address_in, in, opcode,
		 MLX5_CMD_OP_QUERY_ROCE_ADDRESS);

	DEVX_SET(query_roce_address_in, in, roce_address_index,
		 index);
	DEVX_SET(query_roce_address_in, in, vhca_port_num,
		 vhca_port_num);

	ret = mlx5dv_devx_general_cmd(ctx, in, sizeof(in), out, sizeof(out));
	if (ret)
		return ret;

	memcpy(&attr->gid,
	       DEVX_ADDR_OF(query_roce_address_out,
			    out, roce_address.source_l3_address),
	       sizeof(attr->gid));
	memcpy(attr->mac,
	       DEVX_ADDR_OF(query_roce_address_out, out,
			    roce_address.source_mac_47_32),
	       sizeof(attr->mac));
	if (DEVX_GET(query_roce_address_out, out,
		     roce_address.roce_version) == MLX5_ROCE_VERSION_2)
		attr->roce_ver = MLX5_ROCE_VERSION_2;
	else
		attr->roce_ver = MLX5_ROCE_VERSION_1;

	return 0;
}

static int dr_destroy_pd(struct dr_pd *dr_pd)
{
	int ret;

	ret = mlx5dv_devx_obj_destroy(dr_pd->obj);
	if (!ret)
		free(dr_pd);

	return ret;
}

static struct dr_pd *dr_alloc_pd(struct ibv_context *ctx)
{
	uint32_t out[DEVX_ST_SZ_DW(alloc_pd_out)] = {0};
	uint32_t in[DEVX_ST_SZ_DW(alloc_pd_in)] = {0};
	struct mlx5dv_devx_obj *obj;
	struct dr_pd *dr_pd;

	dr_pd = calloc(1, sizeof(*dr_pd));
	if (!dr_pd)
		return NULL;

	DEVX_SET(alloc_pd_in, in, opcode, MLX5_CMD_OP_ALLOC_PD);
	obj = mlx5dv_devx_obj_create(ctx, in, sizeof(in),
				     out, sizeof(out));
	if (!obj)
		goto err_pd_create;

	dr_pd->id = DEVX_GET(alloc_pd_out, out, pd);
	dr_pd->obj = obj;

	return dr_pd;

err_pd_create:
	free(dr_pd);

	return NULL;
}

static int round_up_power_of_two(long long sz)
{
	long long ret;

	for (ret = 1; ret < sz; ret <<= 1)
		; /* nothing */

	if (ret > INT_MAX)
		return -ENOMEM;

	return (int)ret;
}

static int align_queue_size(long long req)
{
	return round_up_power_of_two(req);
}

static int dr_destroy_cq(struct dr_cq *dr_cq)
{
	int ret;

	ret = mlx5dv_devx_obj_destroy(dr_cq->obj);
	if (ret)
		return ret;

	ret = mlx5dv_devx_umem_dereg(dr_cq->db_umem);
	if (ret)
		return ret;

	ret = mlx5dv_devx_umem_dereg(dr_cq->buf_umem);
	if (ret)
		return ret;

	free(dr_cq->db);
	free(dr_cq->buf);
	free(dr_cq);

	return 0;
}

static struct dr_cq *dr_create_cq(struct ibv_context *ctx,
				  struct mlx5dv_devx_uar *uar,
				  int cqen)
{
	uint32_t out[DEVX_ST_SZ_DW(create_cq_out)] = {0};
	uint32_t in[DEVX_ST_SZ_DW(create_cq_in)] = {0};
	struct mlx5dv_devx_umem *umem;
	struct mlx5dv_devx_obj *cq;
	struct mlx5_cqe64 *cqe;
	struct dr_cq *dr_cq;
	int cqe_sz = sizeof(*cqe);
	uint8_t *buf;
	uint32_t eqn;
	int ncqe;
	int err;
	int i;

	dr_cq = calloc(1, sizeof(*dr_cq));
	if (!dr_cq)
		return NULL;

	err = mlx5dv_devx_query_eqn(ctx, 0, &eqn);
	if (err)
		goto err_query_eqn;

	ncqe = align_queue_size(cqen);
	if (ncqe < 0)
		goto err_queue_size;

	buf = memalign(sysconf(_SC_PAGESIZE),
		       cqe_sz * ncqe);
	if (!buf)
		goto err_buf_alloc;

	for (i = 0; i < ncqe; i++) {
		cqe = (struct mlx5_cqe64 *)(buf + i * sizeof(*cqe));
		cqe->op_own = MLX5_CQE_INVALID << 4;
	}
	dr_cq->buf = buf;
	umem = mlx5dv_devx_umem_reg(ctx, buf, cqe_sz * ncqe,
				    IBV_ACCESS_LOCAL_WRITE |
				    IBV_ACCESS_REMOTE_WRITE |
				    IBV_ACCESS_REMOTE_READ);
	if (!umem)
		goto err_buf_umem;

	dr_cq->buf_umem = umem;
	dr_cq->ncqe = ncqe;

	dr_cq->db = memalign(8, 8);
	if (!dr_cq->db)
		goto err_db_alloc;

	dr_cq->db[DR_CQ_SET_CI] = 0;
	dr_cq->db[DR_CQ_ARM_DB] = 0;
	umem = mlx5dv_devx_umem_reg(ctx, dr_cq->db, 8,
				    IBV_ACCESS_LOCAL_WRITE |
				    IBV_ACCESS_REMOTE_WRITE |
				    IBV_ACCESS_REMOTE_READ);
	if (!umem)
		goto err_db_umem;

	dr_cq->db_umem = umem;
	DEVX_SET(create_cq_in, in, opcode, MLX5_CMD_OP_CREATE_CQ);
	DEVX_SET(create_cq_in, in, cq_context.c_eqn, eqn);
	DEVX_SET(create_cq_in, in, cq_context.log_cq_size, dr_ilog2(ncqe));
	DEVX_SET(create_cq_in, in, cq_context.uar_page, uar->page_id);
	DEVX_SET(create_cq_in, in, cq_umem_id, dr_cq->buf_umem->umem_id);
	DEVX_SET(create_cq_in, in, cq_umem_valid, 1);
	DEVX_SET(create_cq_in, in, cq_context.dbr_umem_valid, 1);
	DEVX_SET(create_cq_in, in, cq_context.dbr_umem_id,
		 dr_cq->db_umem->umem_id);

	cq = mlx5dv_devx_obj_create(ctx, in, sizeof(in), out, sizeof(out));
	if (!cq)
		goto err_cq_obj_create;

	dr_cq->id = DEVX_GET(create_cq_out, out, cqn);
	dr_cq->obj = cq;
	dr_cq->uar = uar;

	return dr_cq;

err_cq_obj_create:
	mlx5dv_devx_umem_dereg(dr_cq->db_umem);
err_db_umem:
	free(dr_cq->db);
err_db_alloc:
	mlx5dv_devx_umem_dereg(dr_cq->buf_umem);
err_buf_umem:
	free(dr_cq->buf);
err_buf_alloc:
err_queue_size:
err_query_eqn:
	free(dr_cq);

	return NULL;
}

static int dr_destroy_mr(struct dr_mr *dr_mr)
{
	int ret;

	ret = mlx5dv_devx_obj_destroy(dr_mr->obj);
	if (ret)
		return ret;

	ret = mlx5dv_devx_umem_dereg(dr_mr->buf_umem);
	if (ret)
		return ret;

	free(dr_mr);

	return 0;
}

static struct dr_mr *dr_reg_mr(struct ibv_context *ctx,
			       struct dr_pd *pd, uint8_t *buf, size_t size)
{
	uint32_t out[DEVX_ST_SZ_DW(create_mkey_out)] = {0};
	uint32_t in[DEVX_ST_SZ_DW(create_mkey_in)] = {0};
	struct mlx5dv_devx_umem *buf_umem;
	struct mlx5dv_devx_obj *obj;
	struct dr_mr *dr_mr;

	dr_mr = calloc(1, sizeof(*dr_mr));
	if (!dr_mr)
		return NULL;

	buf_umem = mlx5dv_devx_umem_reg(ctx, buf, size,
					IBV_ACCESS_LOCAL_WRITE |
					IBV_ACCESS_REMOTE_WRITE |
					IBV_ACCESS_REMOTE_READ);
	if (!buf_umem)
		goto err_buf_umem;

	DEVX_SET(create_mkey_in, in, opcode, MLX5_CMD_OP_CREATE_MKEY);
	DEVX_SET(create_mkey_in, in, memory_key_mkey_entry.access_mode_1_0,
		 MLX5_MKC_ACCESS_MODE_MTT);
	DEVX_SET(create_mkey_in, in, memory_key_mkey_entry.a, 1);
	DEVX_SET(create_mkey_in, in, memory_key_mkey_entry.rw, 1);
	DEVX_SET(create_mkey_in, in, memory_key_mkey_entry.rr, 1);
	DEVX_SET(create_mkey_in, in, memory_key_mkey_entry.lw, 1);
	DEVX_SET(create_mkey_in, in, memory_key_mkey_entry.lr, 1);
	DEVX_SET64(create_mkey_in, in, memory_key_mkey_entry.start_addr,
		   (intptr_t)buf);
	DEVX_SET64(create_mkey_in, in, memory_key_mkey_entry.len, size);
	DEVX_SET(create_mkey_in, in, memory_key_mkey_entry.pd,
		 pd->id);
	DEVX_SET(create_mkey_in, in,
		 memory_key_mkey_entry.translations_octword_size, 8);
	DEVX_SET(create_mkey_in, in, memory_key_mkey_entry.log_page_size,
		 dr_ilog2(sysconf(_SC_PAGESIZE)));
	DEVX_SET(create_mkey_in, in, memory_key_mkey_entry.qpn, 0xffffff);
	DEVX_SET(create_mkey_in, in, memory_key_mkey_entry.mkey_7_0, 0x33);
	DEVX_SET(create_mkey_in, in, translations_octword_actual_size, 8);
	DEVX_SET(create_mkey_in, in, mkey_umem_id, buf_umem->umem_id);

	obj = mlx5dv_devx_obj_create(ctx, in,
				     sizeof(in), out, sizeof(out));
	if (!obj)
		goto err_devx_create;

	dr_mr->id = DEVX_GET(create_mkey_out, out, mkey_index) << 8 | 0x33;
	dr_mr->obj = obj;
	dr_mr->buf_umem = buf_umem;
	dr_mr->size = size;
	dr_mr->buf = buf;

	return dr_mr;

err_devx_create:
	mlx5dv_devx_umem_dereg(buf_umem);
err_buf_umem:
	free(dr_mr);

	return NULL;
}

static int calc_send_wqe(struct dr_qp_init_attr *attr)
{
	int inl_size = 0;
	int tot_size;
	int size;

	size = sizeof(struct mlx5_wqe_ctrl_seg) +
		sizeof(struct mlx5_wqe_raddr_seg);
	if (attr->cap.max_inline_data) {
		inl_size = size + align(sizeof(struct mlx5_wqe_inl_data_seg) +
					attr->cap.max_inline_data, 16);
	}

	size += attr->cap.max_send_sge * sizeof(struct mlx5_wqe_data_seg);
	tot_size = max_t(int, size, inl_size);

	return align(tot_size, MLX5_SEND_WQE_BB);
}

static int dr_calc_sq_size(struct dr_qp *dr_qp,
			   struct dr_qp_init_attr *attr)
{
	int wqe_size;
	int wq_size;

	wqe_size = calc_send_wqe(attr);
	if (wqe_size < 0)
		return -EINVAL;

	dr_qp->max_inline_data = wqe_size -
		(sizeof(struct  mlx5_wqe_ctrl_seg) +
		 sizeof(struct mlx5_wqe_raddr_seg)) -
		sizeof(struct mlx5_wqe_inl_data_seg);

	wq_size = round_up_power_of_two(attr->cap.max_send_wr * wqe_size);
	dr_qp->sq.wqe_cnt = wq_size / MLX5_SEND_WQE_BB;
	dr_qp->sq.wqe_shift = dr_ilog2(MLX5_SEND_WQE_BB);
	dr_qp->sq.max_gs = attr->cap.max_send_sge;
	dr_qp->sq.max_post = wq_size / wqe_size;

	return wq_size;
}

static int dr_calc_recv_wqe(struct dr_qp_init_attr *attr)
{
	uint32_t size;
	int num_scatter;

	num_scatter = max_t(uint32_t, attr->cap.max_recv_sge, 1);
	size = sizeof(struct mlx5_wqe_data_seg) * num_scatter;

	size = round_up_power_of_two(size);

	return size;
}

static int dr_calc_rq_size(struct dr_qp *dr_qp,
			   struct dr_qp_init_attr *attr)
{
	int wqe_size;
	int wq_size;

	wqe_size = dr_calc_recv_wqe(attr);
	if (wqe_size < 0)
		return -EINVAL;

	wq_size = round_up_power_of_two(attr->cap.max_recv_wr) * wqe_size;
	wq_size = max(wq_size, MLX5_SEND_WQE_BB);
	dr_qp->rq.wqe_cnt = wq_size / wqe_size;
	dr_qp->rq.wqe_shift = dr_ilog2(wqe_size);
	dr_qp->rq.max_post = 1 << dr_ilog2(wq_size / wqe_size);
	dr_qp->rq.max_gs = wqe_size / sizeof(struct mlx5_wqe_data_seg);

	return wq_size;
}

static int dr_calc_wq_size(struct dr_qp *dr_qp, struct dr_qp_init_attr *attr)
{
	int result;
	int ret;

	ret = dr_calc_sq_size(dr_qp, attr);
	if (ret < 0)
		return ret;

	result = ret;
	ret = dr_calc_rq_size(dr_qp, attr);
	if (ret < 0)
		return ret;

	result += ret;
	dr_qp->sq.offset = ret;
	dr_qp->rq.offset = 0;

	return result;
}

static int alloc_qp_buf(struct dr_qp *dr_qp, int size)
{
	int al_size;
	int ret;

	dr_qp->sq.wqe_head = malloc(dr_qp->sq.wqe_cnt *
				    sizeof(*dr_qp->sq.wqe_head));
	if (!dr_qp->sq.wqe_head)
		return -ENOMEM;

	al_size = align(size, sysconf(_SC_PAGESIZE));
	ret = posix_memalign(&dr_qp->buf.buf, sysconf(_SC_PAGESIZE), al_size);
	if (ret)
		return ret;

	dr_qp->buf.length = al_size;
	memset(dr_qp->buf.buf, 0, dr_qp->buf.length);

	return 0;
}

static int devx_create_qp(struct ibv_context *ctx, struct dr_qp *dr_qp,
			  struct dr_qp_init_attr *attr)
{
	u8 in[DEVX_ST_SZ_BYTES(create_qp_in)] = {0};
	u8 out[DEVX_ST_SZ_BYTES(create_qp_out)] = {0};
	void *qpc;

	DEVX_SET(create_qp_in, in, opcode, MLX5_CMD_OP_CREATE_QP);
	qpc = DEVX_ADDR_OF(create_qp_in, in, qpc);
	DEVX_SET(qpc, qpc, st, MLX5_QPC_ST_RC);
	DEVX_SET(qpc, qpc, pm_state, MLX5_QPC_PM_STATE_MIGRATED);
	DEVX_SET(qpc, qpc, pd, attr->pdn);
	DEVX_SET(qpc, qpc, uar_page, attr->uar->page_id);
	DEVX_SET(qpc, qpc, cqn_snd, attr->cq->id);
	DEVX_SET(qpc, qpc, cqn_rcv, attr->cq->id);
	DEVX_SET(qpc, qpc, log_sq_size, dr_ilog2(dr_qp->sq.wqe_cnt));
	DEVX_SET(qpc, qpc, log_rq_stride, dr_qp->rq.wqe_shift - 4);
	DEVX_SET(qpc, qpc, log_rq_size, dr_ilog2(dr_qp->rq.wqe_cnt));
	DEVX_SET(create_qp_in, in, wq_umem_id, dr_qp->buf_umem->umem_id);
	DEVX_SET(create_qp_in, in, wq_umem_valid, 1);
	DEVX_SET(qpc, qpc, dbr_umem_id, dr_qp->db_umem->umem_id);

	dr_qp->obj = mlx5dv_devx_obj_create(ctx, in,
					    sizeof(in), out, sizeof(out));
	if (!dr_qp->obj)
		return -EINVAL;

	dr_qp->id = DEVX_GET(create_qp_out, out, qpn);
	dr_qp->uar = attr->uar;
	attr->cq->qp = dr_qp;

	return 0;
}

static int dr_destroy_qp(struct dr_qp *dr_qp)
{
	int ret;

	ret = mlx5dv_devx_obj_destroy(dr_qp->obj);
	if (ret)
		return ret;

	ret = mlx5dv_devx_umem_dereg(dr_qp->buf_umem);
	if (ret)
		return ret;

	ret = mlx5dv_devx_umem_dereg(dr_qp->db_umem);
	if (ret)
		return ret;

	free(dr_qp->db);
	free(dr_qp->sq.wqe_head);
	free(dr_qp->buf.buf);
	free(dr_qp);

	return 0;
}

static struct dr_qp *dr_create_qp(struct ibv_context *ctx,
				  struct dr_qp_init_attr *attr)
{
	struct dr_qp *dr_qp;
	int ret;

	if (attr->qp_type != IBV_QPT_RC ||
	    attr->cq->qp)
		return NULL;

	dr_qp = calloc(1, sizeof(*dr_qp));
	if (!dr_qp)
		return NULL;

	ret = dr_calc_wq_size(dr_qp, attr);
	if (ret < 0)
		return NULL;

	if (alloc_qp_buf(dr_qp, ret))
		goto err_alloc_bufs;

	dr_qp->sq_start = dr_qp->buf.buf + dr_qp->sq.offset;
	dr_qp->sq.qend = dr_qp->buf.buf + dr_qp->sq.offset +
		(dr_qp->sq.wqe_cnt << dr_qp->sq.wqe_shift);
	dr_qp->rq.head = 0;
	dr_qp->rq.tail = 0;
	dr_qp->sq.cur_post = 0;

	dr_qp->db = memalign(8, 8);
	if (!dr_qp->db)
		goto err_db_alloc;

	dr_qp->db[MLX5_RCV_DBR] = 0;
	dr_qp->db[MLX5_SND_DBR] = 0;
	dr_qp->db_umem = mlx5dv_devx_umem_reg(ctx, dr_qp->db, 8,
					      IBV_ACCESS_LOCAL_WRITE |
					      IBV_ACCESS_REMOTE_WRITE |
					      IBV_ACCESS_REMOTE_READ);
	if (!dr_qp->db_umem)
		goto err_db_umem;

	dr_qp->buf_umem = mlx5dv_devx_umem_reg(ctx, dr_qp->buf.buf,
					       dr_qp->buf.length,
					       IBV_ACCESS_LOCAL_WRITE |
					       IBV_ACCESS_REMOTE_WRITE |
					       IBV_ACCESS_REMOTE_READ);
	if (!dr_qp->buf_umem)
		goto err_buf_umem;

	ret = devx_create_qp(ctx, dr_qp, attr);
	if (ret)
		goto err_qp_create;

	return dr_qp;

err_qp_create:
	mlx5dv_devx_umem_dereg(dr_qp->buf_umem);
err_buf_umem:
	mlx5dv_devx_umem_dereg(dr_qp->db_umem);
err_db_umem:
	free(dr_qp->db);
err_db_alloc:
err_alloc_bufs:
	if (dr_qp->sq.wqe_head)
		free(dr_qp->sq.wqe_head);
	if (dr_qp->buf.buf)
		free(dr_qp->buf.buf);

	free(dr_qp);

	return NULL;
}

static int dr_modify_qp_rst2init(struct ibv_context *ctx,
				 struct dr_qp *dr_qp, uint16_t port)
{
	uint32_t in[DEVX_ST_SZ_DW(rst2init_qp_in)] = {0};
	uint32_t out[DEVX_ST_SZ_DW(rst2init_qp_out)] = {0};
	void *qpc = DEVX_ADDR_OF(rst2init_qp_in, in, qpc);

	DEVX_SET(rst2init_qp_in, in, opcode, MLX5_CMD_OP_RST2INIT_QP);
	DEVX_SET(rst2init_qp_in, in, qpn, dr_qp->id);

	DEVX_SET(qpc, qpc, primary_address_path.vhca_port_num, port);
	DEVX_SET(qpc, qpc, pm_state, MLX5_QPC_PM_STATE_MIGRATED);
	DEVX_SET(qpc, qpc, rre, 1);
	DEVX_SET(qpc, qpc, rwe, 1);

	return mlx5dv_devx_obj_modify(dr_qp->obj, in,
				      sizeof(in), out, sizeof(out));
}

static int dr_modify_qp_init2rtr(struct ibv_context *ctx,
				 struct dr_qp *dr_qp,
				 struct dr_qp_rtr_attr *attr)
{
	uint32_t out[DEVX_ST_SZ_DW(init2rtr_qp_out)] = {0};
	uint32_t in[DEVX_ST_SZ_DW(init2rtr_qp_in)] = {0};
	void *qpc = DEVX_ADDR_OF(init2rtr_qp_in, in, qpc);

	DEVX_SET(init2rtr_qp_in, in, opcode, MLX5_CMD_OP_INIT2RTR_QP);
	DEVX_SET(init2rtr_qp_in, in, qpn, dr_qp->id);

	DEVX_SET(qpc, qpc, mtu, attr->mtu);
	DEVX_SET(qpc, qpc, log_msg_max, 30);
	DEVX_SET(qpc, qpc, remote_qpn, attr->qp_num);
	DEVX_SET(qpc, qpc, next_rcv_psn, attr->rq_psn);
	memcpy(DEVX_ADDR_OF(qpc, qpc, primary_address_path.rmac_47_32),
	       attr->dgid_attr.mac, sizeof(attr->dgid_attr.mac));
	memcpy(DEVX_ADDR_OF(qpc, qpc, primary_address_path.rgid_rip),
	       attr->dgid_attr.gid.raw,
	       DEVX_FLD_SZ_BYTES(qpc, primary_address_path.rgid_rip));
	DEVX_SET(qpc, qpc, primary_address_path.src_addr_index,
		 attr->sgid_index);
	if (attr->dgid_attr.roce_ver == MLX5_ROCE_VERSION_2)
		DEVX_SET(qpc, qpc, primary_address_path.udp_sport, 49861 + 50);
	DEVX_SET(qpc, qpc, primary_address_path.vhca_port_num, attr->port_num);
	DEVX_SET(qpc, qpc, min_rnr_nak, 1);

	return mlx5dv_devx_obj_modify(dr_qp->obj, in,
				      sizeof(in), out, sizeof(out));
}

static int dr_modify_qp_rtr2rts(struct ibv_context *ctx,
				struct dr_qp *dr_qp,
				struct dr_qp_rts_attr *attr)
{
	uint32_t in[DEVX_ST_SZ_DW(rtr2rts_qp_in)] = {0};
	uint32_t out[DEVX_ST_SZ_DW(rtr2rts_qp_out)] = {0};
	void *qpc = DEVX_ADDR_OF(rtr2rts_qp_in, in, qpc);

	DEVX_SET(rtr2rts_qp_in, in, opcode, MLX5_CMD_OP_RTR2RTS_QP);
	DEVX_SET(rtr2rts_qp_in, in, qpn, dr_qp->id);

	DEVX_SET(qpc, qpc, log_ack_req_freq, 0);
	DEVX_SET(qpc, qpc, retry_count, attr->retry_cnt);
	DEVX_SET(qpc, qpc, rnr_retry, attr->rnr_retry);
	DEVX_SET(qpc, qpc, next_send_psn, attr->sq_psn);

	return mlx5dv_devx_obj_modify(dr_qp->obj, in,
				      sizeof(in), out, sizeof(out));
}

struct dr_sg_copy_ptr {
	int	index;
	int	offset;
};

struct dr_wqe_inline_seg {
	__be32		byte_count;
};

static inline int set_data_inl_seg(struct dr_qp *dr_qp,
				   struct ibv_send_wr *wr,
				   void *wqe, int *sz,
				   struct dr_sg_copy_ptr *sg_copy_ptr)
{
	int offset = sg_copy_ptr->offset;
	struct dr_wqe_inline_seg *seg;
	void *qend = dr_qp->sq.qend;
	int inl = 0;
	void *addr;
	int copy;
	int len;
	int i;

	seg = wqe;
	wqe += sizeof(*seg);
	for (i = sg_copy_ptr->index; i < wr->num_sge; ++i) {
		addr = (void *) (unsigned long)(wr->sg_list[i].addr + offset);
		len  = wr->sg_list[i].length - offset;
		inl += len;
		offset = 0;

		if (unlikely(inl > dr_qp->max_inline_data))
			return -ENOMEM;

		if (unlikely(wqe + len > qend)) {
			copy = qend - wqe;
			memcpy(wqe, addr, copy);
			addr += copy;
			len -= copy;
			wqe = dr_qp->sq_start;
		}
		memcpy(wqe, addr, len);
		wqe += len;
	}

	if (likely(inl)) {
		seg->byte_count = htobe32(inl | MLX5_INLINE_SEG);
		*sz = align(inl + sizeof seg->byte_count, 16) / 16;
	} else {
		*sz = 0;
	}

	return 0;
}

static inline void dr_post_send_db(struct dr_qp *dr_qp, int nreq, void *ctrl)
{
	if (unlikely(!nreq))
		return;

	dr_qp->sq.head += nreq;

	/*
	 * Make sure that descriptors are written before
	 * updating doorbell record and ringing the doorbell
	 */
	asm volatile("" ::: "memory");
	dr_qp->db[MLX5_SND_DBR] = htobe32(dr_qp->sq.cur_post & 0xffff);

	asm volatile("" ::: "memory");

	*(uint64_t *)(uint8_t *)dr_qp->uar->reg_addr = *(__be64 *)ctrl;

	asm volatile("" ::: "memory");
}

static inline void set_raddr_seg(struct mlx5_wqe_raddr_seg *rseg,
				 uint64_t remote_addr, uint32_t rkey)
{
	rseg->raddr    = htobe64(remote_addr);
	rseg->rkey     = htobe32(rkey);
	rseg->reserved = 0;
}

static void set_data_ptr_seg(struct mlx5_wqe_data_seg *dseg, struct ibv_sge *sg,
			     int offset)
{
	dseg->byte_count = htobe32(sg->length - offset);
	dseg->lkey       = htobe32(sg->lkey);
	dseg->addr       = htobe64(sg->addr + offset);
}

static const uint32_t dr_ib_opcode[] = {
	[IBV_WR_RDMA_WRITE]		= MLX5_OPCODE_RDMA_WRITE,
	[IBV_WR_RDMA_READ]		= MLX5_OPCODE_RDMA_READ,
};

static int dr_wq_overflow(struct dr_wq *wq, int nreq)
{
	unsigned cur;

	cur = wq->head - wq->tail;
	if (cur + nreq < wq->max_post)
		return 0;

	cur = wq->head - wq->tail;

	return cur + nreq >= wq->max_post;
}

/* Assume post_send and poll can't be called at the same time */
static int dr_post_send(struct dr_qp *dr_qp,
			struct ibv_send_wr *wr)
{
	struct dr_sg_copy_ptr sg_copy_ptr = {.index = 0, .offset = 0};
	struct mlx5_wqe_ctrl_seg *ctrl = NULL;
	struct mlx5_wqe_data_seg *dpseg;
	void *qend = dr_qp->sq.qend;
	uint32_t dr_opcode;
	unsigned idx;
	int size = 0;
	int inl = 0;
	int err = 0;
	void *seg;
	int nreq;
	int i;

	for (nreq = 0; wr; ++nreq, wr = wr->next) {
		if (unlikely(dr_wq_overflow(&dr_qp->sq, nreq))) {
			err = ENOMEM;
			goto out;
		}

		if (unlikely(wr->num_sge > dr_qp->sq.max_gs)) {
			err = ENOMEM;
			goto out;
		}

		idx = dr_qp->sq.cur_post & (dr_qp->sq.wqe_cnt - 1);
		ctrl = seg = dr_qp->sq_start + (idx << MLX5_SEND_WQE_SHIFT);
		*(uint32_t *)(seg + 8) = 0;
		ctrl->imm = 0;
		ctrl->fm_ce_se = wr->send_flags & IBV_SEND_SIGNALED ?
			MLX5_WQE_CTRL_CQ_UPDATE : 0;

		seg += sizeof(*ctrl);
		size = sizeof(*ctrl) / 16;

		/* Only RDMA_WRITE/RDMA_READ */
		set_raddr_seg(seg, wr->wr.rdma.remote_addr,
			      wr->wr.rdma.rkey);
		seg  += sizeof(struct mlx5_wqe_raddr_seg);
		size += sizeof(struct mlx5_wqe_raddr_seg) / 16;

		if (wr->send_flags & IBV_SEND_INLINE && wr->num_sge) {
			int sz;

			err = set_data_inl_seg(dr_qp, wr, seg, &sz,
					       &sg_copy_ptr);
			if (unlikely(err))
				goto out;
			inl = 1;
			size += sz;
		} else {
			dpseg = seg;
			for (i = sg_copy_ptr.index; i < wr->num_sge; ++i) {
				if (unlikely(dpseg == qend)) {
					seg = dr_qp->sq_start;
					dpseg = seg;
				}
				if (likely(wr->sg_list[i].length)) {
					set_data_ptr_seg(dpseg, wr->sg_list + i,
							 sg_copy_ptr.offset);
					sg_copy_ptr.offset = 0;
					++dpseg;
					size += sizeof(struct mlx5_wqe_data_seg) / 16;
				}
			}
		}
		dr_opcode = dr_ib_opcode[wr->opcode];
		ctrl->opmod_idx_opcode =
			htobe32(((dr_qp->sq.cur_post & 0xffff) << 8) |
				dr_opcode);
		ctrl->qpn_ds = htobe32(size | (dr_qp->id << 8));
		dr_qp->sq.wqe_head[idx] = dr_qp->sq.head + nreq;
		dr_qp->sq.cur_post += DIV_ROUND_UP(size * 16, MLX5_SEND_WQE_BB);
	}
out:
	dr_post_send_db(dr_qp, nreq, ctrl);
	return err;
}

static int read_data(struct global_ctx *gl_ctx)
{
	struct ibv_send_wr wr_post[1] = {};
	struct ibv_sge sg[1] = {};

	sg[0].addr = (intptr_t)gl_ctx->dr_mr_read->buf;
	sg[0].length = SINGLE_BUF_SIZE;
	sg[0].lkey = gl_ctx->dr_mr_read->id;

	wr_post[0].sg_list = &sg[0];
	wr_post[0].num_sge = 1;
	wr_post[0].opcode = IBV_WR_RDMA_READ;
	wr_post[0].send_flags = IBV_SEND_SIGNALED;

	wr_post[0].wr.rdma.remote_addr =
		(uintptr_t)(gl_ctx->dr_mr_write->buf);
	wr_post[0].wr.rdma.rkey = gl_ctx->dr_mr_write->id;
	wr_post[0].next = NULL;

	return dr_post_send(gl_ctx->dr_qp, wr_post);
}

static int write_data(struct global_ctx *gl_ctx)
{
	struct ibv_send_wr wr_post[1] = {};
	struct ibv_sge sg[1] = {};

	sg[0].addr = (intptr_t)gl_ctx->dr_mr_src->buf;
	sg[0].length = SINGLE_BUF_SIZE;
	sg[0].lkey = gl_ctx->dr_mr_src->id;

	wr_post[0].sg_list = &sg[0];
	wr_post[0].num_sge = 1;
	wr_post[0].opcode = IBV_WR_RDMA_WRITE;
	wr_post[0].send_flags = IBV_SEND_SIGNALED;

	wr_post[0].wr.rdma.remote_addr =
		(uintptr_t)(gl_ctx->dr_mr_write->buf);
	wr_post[0].wr.rdma.rkey = gl_ctx->dr_mr_write->id;
	wr_post[0].next = NULL;

	return dr_post_send(gl_ctx->dr_qp, wr_post);
}

enum {
	CQ_OK = 0,
	CQ_EMPTY = -1,
	CQ_POLL_ERR= -2
};

static inline void *get_cqe(struct dr_cq *dr_cq, int n)
{
	return dr_cq->buf + n * sizeof(struct mlx5_cqe64);
}

static inline void *get_sw_cqe(struct dr_cq *dr_cq, int n)
{
	struct mlx5_cqe64 *cqe64 = get_cqe(dr_cq, n & (dr_cq->ncqe - 1));

	if (likely(mlx5dv_get_cqe_opcode(cqe64) != MLX5_CQE_INVALID) &&
	    !((cqe64->op_own & MLX5_CQE_OWNER_MASK) ^
	      !!(n & dr_cq->ncqe)))
		return cqe64;
	else
		return NULL;
}

static inline int dr_get_next_cqe(struct dr_cq *dr_cq,
				  struct mlx5_cqe64 **pcqe64)
{
	struct mlx5_cqe64 *cqe64;

	cqe64 = get_sw_cqe(dr_cq, dr_cq->cons_index);
	if (!cqe64)
		return CQ_EMPTY;

	++dr_cq->cons_index;
	/*
	 * Make sure we read CQ entry contents after we've checked the
	 * ownership bit.
	 */
	asm volatile("" ::: "memory");

	*pcqe64 = cqe64;

	return CQ_OK;
}

static inline int dr_parse_cqe(struct dr_cq *dr_cq, struct mlx5_cqe64 *cqe64)
{
	uint16_t wqe_ctr;
	uint8_t opcode;
	int idx;

	wqe_ctr = be16toh(cqe64->wqe_counter);
	opcode = mlx5dv_get_cqe_opcode(cqe64);
	if (opcode == MLX5_CQE_REQ_ERR){
		idx = wqe_ctr & (dr_cq->qp->sq.wqe_cnt - 1);
		dr_cq->qp->sq.tail = dr_cq->qp->sq.wqe_head[idx] + 1;
	} else if (opcode == MLX5_CQE_RESP_ERR) {
		++dr_cq->qp->sq.tail;
	} else {
		idx = wqe_ctr & (dr_cq->qp->sq.wqe_cnt - 1);
		dr_cq->qp->sq.tail = dr_cq->qp->sq.wqe_head[idx] + 1;

		return CQ_OK;
	}

	return CQ_POLL_ERR;
}

static inline int dr_poll_one(struct dr_cq *dr_cq)
{
	struct mlx5_cqe64 *cqe64;
	int err;

	err = dr_get_next_cqe(dr_cq, &cqe64);
	if (err)
		return CQ_EMPTY;

	return dr_parse_cqe(dr_cq, cqe64);
}

static int dr_poll_cq(struct dr_cq *dr_cq, int ne)
{
	int npolled;
	int err = 0;

	for (npolled = 0; npolled < ne; ++npolled) {
		err = dr_poll_one(dr_cq);
		if (err != CQ_OK)
			break;
	}
	dr_cq->db[DR_CQ_SET_CI] = htobe32(dr_cq->cons_index &
					    0xffffff);
	return err == CQ_POLL_ERR ? err : npolled;
}

static void print_bufs(struct global_ctx *ctx)
{
	int i;

	printf("Source buffer:\n");
	printf("\t");
	for (i = 0; i < SINGLE_BUF_SIZE; i++)
		printf("%x", ctx->dr_mr_src->buf[i]);
	printf("\nWrite to buffer:\n");
	printf("\t");
	for (i = 0; i < SINGLE_BUF_SIZE; i++)
		printf("%x", ctx->dr_mr_write->buf[i]);
	printf("\nRead to buffer:\n");
	printf("\t");
	for (i = 0; i < SINGLE_BUF_SIZE; i++)
		printf("%x", ctx->dr_mr_read->buf[i]);
	printf("\n");
}

static void print_summery(struct global_ctx *ctx,
			  struct dr_qp_rtr_attr *rtr_attr)
{
	char gid[INET6_ADDRSTRLEN + 1] = {};

	inet_ntop(AF_INET6, rtr_attr->dgid_attr.gid.raw,
		  gid, sizeof(gid));

	printf("Summery:\n");
	printf("\tIB device: %s\n", ctx->ctx->device->name);
	printf("\tRC QPN: 0x%X\n", ctx->dr_qp->id);
	printf("\tCQN: 0x%X\n", ctx->dr_cq->id);
	printf("\tPDN: 0x%X\n", ctx->dr_pd->id);
	printf("\tUAR base address: 0x%p\n", ctx->uar->base_addr);
	printf("\tUAR register address: 0x%p\n", ctx->uar->reg_addr);
	printf("\tSRC DGID/SGID: %s\n", gid);
	printf("\tSRC buffer rkey/lkey: 0x%X\n", ctx->dr_mr_src->id);
	printf("\tWRITE buffer rkey/lkey: 0x%X\n", ctx->dr_mr_write->id);
	printf("\tREAD buffer rkey/lkey: 0x%X\n\n", ctx->dr_mr_read->id);
}

static int do_rdma(struct global_ctx *ctx)
{
	int err;

	printf("Before RDMA operations:\n");
	print_bufs(ctx);
	if (write_data(ctx)) {
		printf("bad write post send\n");
		return -EINVAL;
	}

	do {
		err = dr_poll_cq(ctx->dr_cq, 1);
		if (err < 0) {
			printf("Bad completion (write)\n");
			return -EINVAL;
		}
	} while (!err);

	printf("\nAfter RDMA_WRITE:\n");
	print_bufs(ctx);

	if (read_data(ctx)) {
		printf("bad read post send\n");
		return -EINVAL;
	}

	do {
		err = dr_poll_cq(ctx->dr_cq, 1);
		if (err < 0) {
			printf("Bad completion (read)\n");
			return -EINVAL;
		}
	} while (!err);

	printf("\nAfter RDMA_READ:\n");
	print_bufs(ctx);

	return 0;
}

int main(int argc, char **argv)
{
	struct mlx5dv_context_attr mlx5_attr = {.flags =
		MLX5DV_CONTEXT_FLAGS_DEVX };
	struct dr_qp_init_attr init_attr = {};
	struct dr_qp_rts_attr rts_attr = {};
	struct dr_qp_rtr_attr rtr_attr = {};
	struct global_ctx global_ctx = {};
	struct ibv_device **dev_list;
	struct ibv_device *ib_dev;
	struct ibv_context *ctx;
	uint8_t *buf;
	int cq_size;
	int ret;
	int i;

	buf = calloc(1, SINGLE_BUF_SIZE * 3);
	if (!buf) {
		printf("Can't allocate buffer\n");
		return -1;
	}

	buf[0] = 0xde;
	buf[1] = 0xad;
	buf[2] = 0xbe;
	buf[3] = 0xef;

	if (argc != 2) {
		printf("Pass ib name\n");
		ret = -EINVAL;
		goto free_buf;
	}

	dev_list = ibv_get_device_list(NULL);
	if (!dev_list) {
		perror("Failed to get IB devices list");
		ret = -EINVAL;
		goto free_buf;
	}

	for (i = 0; dev_list[i]; ++i)
		if (!strcmp(ibv_get_device_name(dev_list[i]), argv[1]))
			break;
	ib_dev = dev_list[i];
	if (!ib_dev) {
		printf("IB device %s not found\n", argv[1]);
		ret = -EINVAL;
		goto free_dev_list;
	}

	ctx = mlx5dv_open_device(ib_dev, &mlx5_attr);
	if (!ctx) {
		printf("can't open mlx5 device %s\n", argv[1]);
		ret = -EINVAL;
		goto free_dev_list;
	}

	global_ctx.ctx = ctx;
	global_ctx.uar = mlx5dv_devx_alloc_uar(global_ctx.ctx, 0);
	if (!global_ctx.uar) {
		printf("Can't allocate UAR\n");
		ret = -EINVAL;
		goto free_resources;
	}

	global_ctx.dr_pd = dr_alloc_pd(global_ctx.ctx);
	if (!global_ctx.dr_pd) {
		printf("Can't create pd\n");
		ret = -EINVAL;
		goto free_resources;
	}

	cq_size = QUEUE_SIZE + 1;
	global_ctx.dr_cq = dr_create_cq(global_ctx.ctx, global_ctx.uar,
					cq_size);
	if (!global_ctx.dr_cq) {
		printf("Can't create cq\n");
		ret = -EINVAL;
		goto free_resources;
	}

	global_ctx.dr_mr_src = dr_reg_mr(global_ctx.ctx, global_ctx.dr_pd,
					 buf, SINGLE_BUF_SIZE);
	if (!global_ctx.dr_mr_src) {
		printf("Can't create mr\n");
		ret = -EINVAL;
		goto free_resources;
	}

	global_ctx.dr_mr_write = dr_reg_mr(global_ctx.ctx, global_ctx.dr_pd,
					   buf + SINGLE_BUF_SIZE,
					   SINGLE_BUF_SIZE);
	if (!global_ctx.dr_mr_write) {
		printf("Can't create mr\n");
		ret = -EINVAL;
		goto free_resources;
	}

	global_ctx.dr_mr_read = dr_reg_mr(global_ctx.ctx, global_ctx.dr_pd,
					  buf + 2 * SINGLE_BUF_SIZE,
					  SINGLE_BUF_SIZE);
	if (!global_ctx.dr_mr_read) {
		printf("Can't create mr\n");
		ret = -EINVAL;
		goto free_resources;
	}

	init_attr.cap.max_send_wr       = QUEUE_SIZE;
	init_attr.cap.max_recv_wr       = 1;
	init_attr.cap.max_send_sge      = SG_LIST_SIZE;
	init_attr.cap.max_recv_sge      = SG_LIST_SIZE;
	init_attr.cap.max_inline_data   = 32;
	init_attr.qp_type               = IBV_QPT_RC;
	init_attr.pdn = global_ctx.dr_pd->id;
	init_attr.cq = global_ctx.dr_cq;
	init_attr.uar = global_ctx.uar;

	global_ctx.dr_qp = dr_create_qp(global_ctx.ctx, &init_attr);
	if (!global_ctx.dr_qp) {
		printf("Can't create QP\n");
		ret = -EINVAL;
		goto free_resources;
	}

	if (dr_modify_qp_rst2init(global_ctx.ctx, global_ctx.dr_qp, 1)) {
		printf("Can't move to INIT\n");
		ret = -EINVAL;
		goto free_resources;
	}

	rtr_attr.mtu = IBV_MTU_1024;
	rtr_attr.qp_num = global_ctx.dr_qp->id;
	rtr_attr.rq_psn = 1;
	rtr_attr.min_rnr_timer = 12;
	rtr_attr.port_num = 1;
	rtr_attr.sgid_index = 1;

	if (dr_query_gid(ctx, rtr_attr.sgid_index,
			 rtr_attr.port_num, &rtr_attr.dgid_attr)) {
		printf("Can't query GID\n");
		ret = -EINVAL;
		goto free_resources;
	}

	if (dr_modify_qp_init2rtr(global_ctx.ctx, global_ctx.dr_qp,
				  &rtr_attr)) {
		printf("Can't modify to RTR\n");
		ret = -EINVAL;
		goto free_resources;
	}

	rts_attr.timeout = 14;
	rts_attr.retry_cnt = 7;
	rts_attr.rnr_retry = 7;
	rts_attr.sq_psn = 1;

	if (dr_modify_qp_rtr2rts(global_ctx.ctx, global_ctx.dr_qp,
				 &rts_attr)) {
		printf("Can't modify to RTS\n");
		ret = -EINVAL;
		goto free_resources;
	}

	print_summery(&global_ctx, &rtr_attr);

	ret = do_rdma(&global_ctx);
	if (ret)
		goto free_resources;

free_resources:
	if (global_ctx.dr_qp)
		dr_destroy_qp(global_ctx.dr_qp);
	if (global_ctx.dr_cq)
		dr_destroy_cq(global_ctx.dr_cq);
	if (global_ctx.dr_mr_src)
		dr_destroy_mr(global_ctx.dr_mr_src);
	if (global_ctx.dr_mr_write)
		dr_destroy_mr(global_ctx.dr_mr_write);
	if (global_ctx.dr_mr_read)
		dr_destroy_mr(global_ctx.dr_mr_read);
	if (global_ctx.dr_pd)
		dr_destroy_pd(global_ctx.dr_pd);
	if (global_ctx.uar)
		mlx5dv_devx_free_uar(global_ctx.uar);
	if (global_ctx.ctx)
		ibv_close_device(global_ctx.ctx);
free_dev_list:
	ibv_free_device_list(dev_list);
free_buf:
	free(buf);

	return ret;
}
