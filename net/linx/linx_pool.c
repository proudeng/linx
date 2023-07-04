/*
 * Copyright (C) 2011-2019 by Enea Embedded Technology AB.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * Redistributions of source code must retain the above copyright notice, this
 * list of conditions and the following disclaimer.
 * Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 * Neither the name of Enea Software AB nor the names of its
 * contributors may be used to endorse or promote products derived from this
 * software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <linux/version.h>
#include <linux/list.h>
#include <linux/spinlock.h>
#include <linux/linx_ioctl.h>
#include <linux/mm.h>
#include <linx_mem.h>
#include <linx_pool.h>
#include <linx_assert.h>
#include <linx_compat32.h>
#include <asm/pgtable.h>
#include <linux/ioport.h>
#include <asm/io.h>
#include <linux/module.h>
#include <linux/errno.h>


#ifndef likely
#define likely(x)	__builtin_expect(!!(x), 1)
#endif
#ifndef unlikely
#define unlikely(x)	__builtin_expect(!!(x), 0)
#endif

#ifdef CONFIG_64BIT
typedef uint64_t POOL_ADDR;
#else
typedef uint32_t POOL_ADDR;
#endif

struct buffer_control_block {
	/* keep sig_adm structure 8-bytes aligned for 64-bit architecture
	 * (assumption is that pool alignment will be 8-bytes or higher) */
	struct list_head	link;
	uint64_t			list_idx;
	void				*owner;
	char				sig_adm[SIZEOF_SIGADM];
};

struct free_block_list {
	struct list_head	head_a;
	struct list_head	head_na;
	uint32_t			buffer_size;
	uint32_t			num_blocks_a;
	uint32_t			num_blocks_na;
};

struct linx_pool {
	struct free_block_list	*free_lists;
	void					*phys_base_addr;
	void					*base_ptr;
	void					*free_ptr;
	uint32_t				pool_size;
	spinlock_t				spinlock;
	uint32_t				num_fails;
	uint32_t				num_succeed;
	uint32_t				used_size;
	uint32_t				s_alloc_count;
	uint32_t				s_free_count;
	uint16_t				num_lists;
	uint16_t				alignment;
	uint16_t				padding;
	uint8_t					virtual_mem;
};

#define SIGNAL_OVERHEAD												\
	(ROUNDUP(sizeof(struct buffer_control_block), pool.alignment))


#define SIGNAL_HEADROOM_SIZE										\
	(SIGNAL_OVERHEAD -												\
		offsetof(struct buffer_control_block, sig_adm))


#define BUFFER_TO_BCB(buffer)										\
	((struct buffer_control_block *)((char*)(buffer) -				\
	ROUNDUP(sizeof(struct buffer_control_block), pool.alignment)))

#define BCB_TO_BUFFER(bcb)											\
	((char*)(bcb) +													\
	ROUNDUP(sizeof(struct buffer_control_block), pool.alignment))

#define ADM_TO_BUFFER(sig_adm)											\
	((char*)(sig_adm) + SIGNAL_HEADROOM_SIZE)

#if (LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 22))
#define list_first_entry(ptr, type, member) \
	list_entry((ptr)->next, type, member)
#endif

struct linx_pool pool = (const struct linx_pool){ 0 };

static void __print_bcb_info(const void* buffer)
{
	struct buffer_control_block *bcb = BUFFER_TO_BCB(buffer);

#ifdef CONFIG_64BIT
	printk("*** Buffer control block dump for 0x%llx ***\n", (POOL_ADDR)buffer);
	printk(" buffer list index: %lld\n buffer owner: 0x%llx\n",
			bcb->list_idx, (POOL_ADDR)bcb->owner);
#else
	printk("*** Buffer control block dump for 0x%x ***\n", (POOL_ADDR)buffer);
	printk(" buffer list index: %lld\n buffer owner: 0x%x\n",
			 bcb->list_idx, (POOL_ADDR)bcb->owner);
#endif
}

static int __pool_init(uint32_t size,
					uint16_t num_list,
					uint16_t alignment,
					uint32_t s_alloc_count,
					uint32_t s_free_count)
{
	/* Initialize pool data members */
	pool.base_ptr = pool.free_lists = NULL;
	pool.num_fails = 0;
	pool.num_succeed = 0;
	pool.used_size = 0;
	pool.alignment = 1 << alignment;
	pool.pool_size = ROUNDUP(size, pool.alignment);
	pool.virtual_mem = 1;
	pool.s_alloc_count = s_alloc_count;
	pool.s_free_count = s_free_count;
	pool.free_lists = (struct free_block_list  *)
		linx_kmalloc(sizeof(struct free_block_list) * num_list);
	if(unlikely(pool.free_lists == NULL)) {
		return -ENOMEM;
	}

	return 0;
}

static int __pool_map_phys_addr(uint32_t size,
					void *base_addr)
{
	if (request_mem_region((unsigned long)base_addr,
									size,
									"LINX pool") == NULL) {
		printk("Supplied memory for pool could not be reserved\n");
		return -EINVAL;
	}
#if defined(POWERPC) | defined(PPC)
	pool.base_ptr = __ioremap((unsigned long)base_addr,
										size,
										_PAGE_COHERENT);
#else
	pool.base_ptr = ioremap((unsigned long)base_addr, size);
#endif
	pool.phys_base_addr = base_addr;
	pool.virtual_mem = 0;

	return 0;
}

static int __find_block_list(uint32_t size)
{
	int idx, bestfit = -1;
	uint32_t waste = 0xFFFFFFFF;

	for(idx = 0; idx < pool.num_lists; idx++) {
		if(size <= pool.free_lists[idx].buffer_size &&
			waste > pool.free_lists[idx].buffer_size - size) {
			bestfit = idx;
			waste = pool.free_lists[idx].buffer_size - size;
		}
	}

	return bestfit;
}

static void __init_blocks_lists(uint32_t *lists_size)
{
	int idx;

	/* Initialize blocks lists for each block size*/
	for(idx = 0; idx < pool.num_lists; idx++) {
		pool.free_lists[idx].buffer_size = lists_size[idx];
		pool.free_lists[idx].num_blocks_a =
			pool.free_lists[idx].num_blocks_na = 0;
		INIT_LIST_HEAD(&pool.free_lists[idx].head_a);
		INIT_LIST_HEAD(&pool.free_lists[idx].head_na);
	}
}

static void __make_block_available(struct buffer_control_block *bcb,
									int list_idx)
{
	struct LINXSigAdm *sig_adm = (struct LINXSigAdm *)bcb->sig_adm;
	/* Move block to available blocks list */
	list_move_tail(&bcb->link, &pool.free_lists[list_idx].head_a);
	/* Reset block owner */
	bcb->owner = NULL;
	sig_adm->sndrcv.next_sig_offset = 0;
	pool.free_lists[list_idx].num_blocks_a++;
	pool.free_lists[list_idx].num_blocks_na--;
	pool.used_size -= pool.free_lists[list_idx].buffer_size +
		ROUNDUP(sizeof(struct buffer_control_block), pool.alignment);

}

int create_pool(uint32_t size,
		void	 *base_addr,
		uint32_t *blocks_size,
		uint16_t num_list,
		uint16_t alignment,
		uint32_t s_alloc_count,
		uint32_t s_free_count)
{
	int errcode = 0;
	int idx, i;

	uint32_t *lists_size = NULL;
	uint8_t found = 0;
	uint16_t lists_no = 0;
	uint32_t buf_size;

	if(unlikely( (num_list == 0) ||
					(blocks_size == NULL) ||
					((1 << alignment) > size))) {
		return -EINVAL;
	}

	lists_size = (uint32_t *)linx_kmalloc(num_list * sizeof(uint32_t));
	if(unlikely(lists_size == NULL)) {
		return -ENOMEM;
	}
	memset(lists_size, 0, num_list * sizeof(uint32_t));

	/* Initialize lock object */
	spin_lock_init(&pool.spinlock);

	if(unlikely(errcode = __pool_init(size, num_list, alignment,
									  s_alloc_count, s_free_count))) {
		goto cleanup;
	}

	/* Make sure we won't have multiple lists storing blocks
	 * having same size(after rounding up to the alignment)
	 * */
	for(idx = 0; idx < num_list; idx++) {
		buf_size = ROUNDUP(blocks_size[idx], pool.alignment);
		/* Try to find a list having same block size */
		found = 0;
		for(i = 0; i < lists_no; i++) {
			if(lists_size[i] == buf_size) {
				found = 1;
				break;
			}
		}
		/* Add new block size in list */
		if(!found) {
			lists_size[lists_no] = buf_size;
			lists_no++;
		}
	}
	pool.num_lists = lists_no;

	__init_blocks_lists(lists_size);

	if(base_addr != NULL) {
		errcode = __pool_map_phys_addr(pool.pool_size + pool.alignment - 1,
												 base_addr);
		if(unlikely(errcode)) {
			goto cleanup;
		}
	} else {
		/* Allocate memory for pool - make sure pool
			base_address will be properly aligned */
		pool.phys_base_addr = NULL;
		pool.base_ptr =
				linx_vmalloc(pool.pool_size + pool.alignment - 1);
		if(unlikely(pool.base_ptr == NULL)) {
			errcode = -ENOMEM;
			goto cleanup;
		}
	}

	/*
	 * Calculate the necessary padding.
	 * The virtual address returned by ioremap() or vmalloc()
	 * may not be aligned.
	 * We need to alloc beforehand (size + alignment - 1) bytes of memory
	 * to be sure that after the alignment is done there are still
	 * size bytes of pool available.
	 */
	pool.padding = (uint16_t)(ROUNDUP((POOL_ADDR)pool.base_ptr,
					  pool.alignment) -
				  (POOL_ADDR)pool.base_ptr);
	pool.base_ptr = pool.free_ptr = (void *)((char*)pool.base_ptr +
									pool.padding);
	ERROR_ON((((POOL_ADDR)pool.base_ptr) & (~(-1 << alignment))) != 0);

	printk("linx pool created successfully\n");
#ifdef CONFIG_64BIT
	printk(" pool base ptr:0x%llx\n pool padding:%d\n pool alignment:%d\n",
			(POOL_ADDR)pool.base_ptr, pool.padding, pool.alignment);
#else
	printk(" pool base ptr:0x%x\n pool padding:%d\n pool alignment:%d\n",
			(POOL_ADDR)pool.base_ptr, pool.padding, pool.alignment);
#endif
	linx_kfree(lists_size);

	return 0;

cleanup:
	linx_kfree(pool.free_lists);
	if(pool.virtual_mem) {
		linx_vfree(pool.base_ptr);
	}
	linx_kfree(lists_size);

	return errcode;
}

void* get_mem(uint32_t size, void *handle,
		uint32_t *real_size)
{
	struct buffer_control_block *bcb;
	struct buffer_control_block *prev = NULL;
	struct LINXSigAdm *sig_adm;
	void *retVal = NULL;
	uint32_t total_size;
	unsigned long flags;
	int count;
	int i;

	spin_lock_irqsave(&pool.spinlock, flags);

	i = __find_block_list(size);

	if(unlikely(i < 0 || i >= pool.num_lists)) {
		pool.num_fails++;
		goto exit;
	}

	/* Try to allocate pool.s_alloc_count signal.
	 * Success if at least one signal is allocated.
	 */
	for (count = 0; count < pool.s_alloc_count; count++) {
		/* Try to get buffer from corresponding free blocks list */
		if(unlikely(list_empty(&pool.free_lists[i].head_a))) {
			/* If no block found in free list, try to reserve from pool region */
			total_size = pool.free_lists[i].buffer_size +
				ROUNDUP(sizeof(struct buffer_control_block), pool.alignment);
			if(unlikely((POOL_ADDR)pool.free_ptr +	total_size >
					 (POOL_ADDR)pool.base_ptr + pool.pool_size)) {
				pool.num_fails++;
				goto exit;
			}

			bcb = (struct buffer_control_block *)pool.free_ptr;
			pool.free_ptr = ((char *)pool.free_ptr +
							ROUNDUP(sizeof(struct buffer_control_block), pool.alignment) +
							pool.free_lists[i].buffer_size);


			/* Add block directly to unavailable blocks list. It will be moved to
			 * free blocks list when buffer is freed by client.
			 */
			list_add_tail(&bcb->link, &pool.free_lists[i].head_na);
			pool.free_lists[i].num_blocks_na++;
			pool.num_succeed++;
			pool.used_size += total_size;

			bcb->list_idx = i;
		} else {
			/* Grab first block from available blocks list */
			bcb = list_first_entry(&pool.free_lists[i].head_a,
								struct buffer_control_block, link);

			/* Move block to unavailable blocks list */
			list_move_tail(&bcb->link, &pool.free_lists[i].head_na);
			pool.free_lists[i].num_blocks_a--;
			pool.free_lists[i].num_blocks_na++;
			pool.used_size += pool.free_lists[i].buffer_size +
				ROUNDUP(sizeof(struct buffer_control_block), pool.alignment);
			pool.num_succeed++;
		}

		/* If we get here, everything is fine */
		bcb->owner = handle;
		sig_adm = (struct LINXSigAdm *)bcb->sig_adm;
		sig_adm->true_size = pool.free_lists[i].buffer_size;
		sig_adm->sndrcv.next_sig_offset = 0;

		/* Return pointer to first signal. */
		if (count == 0) {
			retVal = BCB_TO_BUFFER(bcb);
			if(real_size != NULL) {
				*real_size = pool.free_lists[i].buffer_size;
			}
		} else {
			sig_adm = (struct LINXSigAdm *)prev->sig_adm;
			sig_adm->sndrcv.next_sig_offset =
					pool_sig_to_offset(BCB_TO_BUFFER(bcb));
		}
		prev = bcb;
	}
exit:
	spin_unlock_irqrestore(&pool.spinlock, flags);
	return retVal;
}

void set_mem_owner(void* buffer, void *handle)
{
	BUFFER_TO_BCB(buffer)->owner = handle;
}

void free_mem(void* buffer, void *handle)
{
	unsigned long flags;
	struct buffer_control_block *bcb;
	struct LINXSigAdm *sig_adm; 
	uint32_t next_offset;

	spin_lock_irqsave(&pool.spinlock, flags);

	while(1) {
		bcb = BUFFER_TO_BCB(buffer);

		if(unlikely(bcb->owner != handle)) {
			__print_bcb_info(buffer);
			ERROR();
			spin_unlock_irqrestore(&pool.spinlock, flags);
			return;
		}

		sig_adm = (struct LINXSigAdm *)bcb->sig_adm;
		next_offset = sig_adm->sndrcv.next_sig_offset;

		__make_block_available(bcb, bcb->list_idx);

		if (next_offset == 0)
			break;

		buffer = pool_offset_to_sig(next_offset);
	}

	spin_unlock_irqrestore(&pool.spinlock, flags);
}

void free_mem_by_owner(void *handle)
{
	int idx;
	unsigned long flags;
	struct list_head *item, *tmp;
	struct buffer_control_block *bcb;

	spin_lock_irqsave(&pool.spinlock, flags);

	for(idx = 0; idx < pool.num_lists; idx++) {
		/* Iterate through unavailable blocks list to identify block */
		list_for_each_safe(item, tmp, &pool.free_lists[idx].head_na) {
			bcb = list_entry(item, struct buffer_control_block, link);
			if(bcb->owner == handle) {
				__make_block_available(bcb, idx);
			}
		}
	}

	spin_unlock_irqrestore(&pool.spinlock, flags);
}

uint32_t get_sig_size(void* buffer)
{
	return pool.free_lists[BUFFER_TO_BCB(buffer)->list_idx].buffer_size;
}

void finalize_pool(void)
{
	if(pool.virtual_mem) {
		pool.base_ptr = (void *)((char*)pool.base_ptr - pool.padding);
		linx_vfree(pool.base_ptr);
	} else {
		iounmap((char*)pool.base_ptr - pool.padding);
		release_mem_region((unsigned long)pool.phys_base_addr,
								  pool.pool_size + pool.alignment - 1);
	}

	linx_kfree(pool.free_lists);
}

void* get_pool_base_addr(void)
{
	return pool.base_ptr;
}

uint32_t get_pool_size(void)
{
	return pool.pool_size;
}

uint32_t get_pool_s_alloc_count(void)
{
	return pool.s_alloc_count;
}

uint32_t get_pool_s_free_count(void)
{
	return pool.s_free_count;
}

uint32_t get_headroom_size(void)
{
	return (SIGNAL_HEADROOM_SIZE);
}

uint8_t is_pool_signal(void* ptr)
{
	return ( ((POOL_ADDR)ptr >= (POOL_ADDR)pool.base_ptr) &&
		 ((POOL_ADDR)ptr < (POOL_ADDR)pool.base_ptr + pool.pool_size) ) ? 1 : 0;
}

uint32_t get_pool_free_size(void)
{
	uint32_t free_size;
	unsigned long flags;

	spin_lock_irqsave(&pool.spinlock, flags);

	free_size = pool.pool_size -
			((char *)pool.free_ptr - (char *)pool.base_ptr);

	spin_unlock_irqrestore(&pool.spinlock, flags);

	return free_size;
}

uint32_t get_pool_overhead(void)
{
	int idx;
	unsigned long flags;
	uint32_t overhead = 0;

	spin_lock_irqsave(&pool.spinlock, flags);

	/* Calculate total overhead of all blocks allocated
	 * from pool (both available and reserved).
	 */
	for(idx = 0; idx < pool.num_lists; idx++) {
		overhead += (pool.free_lists[idx].num_blocks_a +
					pool.free_lists[idx].num_blocks_na) *
					SIGNAL_OVERHEAD;
	}

	spin_unlock_irqrestore(&pool.spinlock, flags);

	return overhead;
}

uint16_t get_pool_alignment(void)
{
	return pool.alignment;
}

uint16_t get_pool_offset(void)
{
#ifdef ERRORCHECKS_MEM
	return pool.padding + sizeof(struct linx_vmalloc_data);
#else
	return pool.padding;
#endif
}

uint16_t get_pool_lists_info(struct linx_pool_list_info *list_info,
							uint16_t num_list)
{
	int idx;
	unsigned long flags;
	int req_lists_no = min(pool.num_lists, num_list);

	spin_lock_irqsave(&pool.spinlock, flags);

	for(idx = 0; idx < req_lists_no; idx++) {
		list_info[idx].block_size = pool.free_lists[idx].buffer_size;
		list_info[idx].allocated = pool.free_lists[idx].num_blocks_na;
		list_info[idx].available = pool.free_lists[idx].num_blocks_a;
	}

	spin_unlock_irqrestore(&pool.spinlock, flags);

	return req_lists_no;
}

char *pool_offset_to_sig(uint32_t offset)
{
	char *signal;

	 if(pool.pool_size < offset) {
		printk("pool_offset_to_sig:ERROR-invalid offset:%u pool_size:%u\n",
				offset, pool.pool_size);
		ERROR();
		return NULL;
	 }

	 signal = (char *)((POOL_ADDR)pool.base_ptr + offset);

	 return signal;
}

uint32_t pool_sig_to_offset(char *signal)
{
	uint32_t offset;

	 offset = (uint32_t)(signal - (char *)pool.base_ptr);
	 if(pool.pool_size < offset) {
		printk("pool_sig_to_offset:ERROR-invalid signal\n");
		ERROR();
		return 0xFFFFFFFF;
	 }

	 return offset;
}

/*
 * Returns the pfn (page frame number) for a vmalloc() or ioremap()
 * virtual address.
 */
unsigned long pool_addr_to_pfn(char *addr)
{
	if (pool.virtual_mem) {
		return vmalloc_to_pfn(addr);
	}

	return (unsigned long)pool_addr_to_phys(addr) >> PAGE_SHIFT;
}

char *pool_addr_to_phys(char *addr)
{
	if (pool.virtual_mem) {
		printk("LINX pool: dedicated memory region not used\n");
		ERROR();
		return addr;
	}
	return pool.phys_base_addr + (addr - (char *)pool.base_ptr);
}
EXPORT_SYMBOL_GPL(pool_addr_to_phys);

char *pool_phys_to_addr(char *p_addr)
{
	if (pool.virtual_mem) {
		printk("LINX pool: dedicated memory region not used\n");
		ERROR();
		return p_addr;
	}
	return pool.base_ptr + (p_addr - (char *)pool.phys_base_addr);
}
EXPORT_SYMBOL_GPL(pool_phys_to_addr);
