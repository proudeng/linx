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
 * */

#ifndef LINX_POOL_H_
#define LINX_POOL_H_

#define ROUNDUP(size, alig) (((size) + (alig) - 1) & -(alig))

int create_pool(uint32_t size,
		void 	 *base_addr,
		uint32_t *blocks_size,
		uint16_t num_list,
		uint16_t alignment,
		uint32_t s_alloc_count,
		uint32_t s_free_count);

void finalize_pool(void);

void* get_mem(uint32_t size,
		void *handle,
		uint32_t *real_size);

void set_mem_owner(void* buffer, void *handle);

void free_mem(void* buffer, void *handle);

void free_mem_by_owner(void *handle);

uint32_t get_sig_size(void* buffer);

char *pool_offset_to_sig(uint32_t offset);

uint32_t pool_sig_to_offset(char *signal);

char *pool_addr_to_phys(char *addr);

char *pool_phys_to_addr(char *p_addr);

void* get_pool_base_addr(void);

uint32_t get_pool_size(void);

uint32_t get_headroom_size(void);

uint8_t is_pool_signal(void* ptr);

uint32_t get_pool_free_size(void);

uint32_t get_pool_overhead(void);

uint32_t get_pool_s_alloc_count(void);

uint32_t get_pool_s_free_count(void);

uint16_t get_pool_alignment(void);

uint16_t get_pool_offset(void);

uint16_t get_pool_lists_info(struct linx_pool_list_info *list_info,
							uint16_t num_list);

unsigned long pool_addr_to_pfn(char *addr);

#endif /* LINX_POOL_H_ */
