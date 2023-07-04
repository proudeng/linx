/*
 * Copyright (c) 2006-2019, Enea Software AB
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

#include <assert.h>
#include <errno.h>
#include <linx.h>
#include <linx_ioctl.h>
#include <linx_socket.h>
#include <linx_types.h>
#include <malloc.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/poll.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/mman.h>
#ifdef SHARE_VIRTUAL_POOL
#include <pthread.h>
#endif

#ifndef likely
#define likely(x)	__builtin_expect(!!(x), 1)
#endif
#ifndef unlikely
#define unlikely(x)	__builtin_expect(!!(x), 0)
#endif

#ifndef NDEBUG
#define LINX_MAGIC	0x12344321
#endif

#ifndef SOCK_CLOEXEC
#define SOCK_CLOEXEC 0
#endif

#define ptr_to_uint64(ptr)	((uint64_t)(unsigned long)(ptr))
#define uint64_to_ptr(val)	((void *)(unsigned long)(val))

struct LINX_IPC {
	struct Link owned_sig;
#ifndef NDEBUG
	uint32_t magic;
#endif
	int socket;
	LINX_SPID spid;
	struct LINXSigAdm *free_buffer;
	uint32_t *pool_alloc_head;
	uint32_t *pool_block_size;
	uint32_t pool_free_head;
	uint32_t free_list_size;
	char *pool_area;
	uint32_t pool_size;
	uint32_t pool_signal_headroom;
	uint32_t pool_free_count;
	uint16_t pool_offset;
	uint16_t pool_num_lists;
};


/* Buffer signal size for linx_receive(), read from kernel */
static int linx_recv_sigsize;

union LINX_SIGNAL {
	LINX_SIGSELECT sig_no;
};

#ifdef SHARE_VIRTUAL_POOL
static char* processPoolAreaP;
static int poolUseCount;
pthread_mutex_t vp_mutex = PTHREAD_MUTEX_INITIALIZER;
#endif

static __inline int is_pool_signal(const LINX *linx, const char *ptr)
{
	if (ptr >= linx->pool_area &&
		ptr < (linx->pool_area + linx->pool_size))
		return 1;
	return 0;
}

static int
find_block_list(const LINX *linx, uint32_t size)
{
	int idx, bestfit = -1;
	uint32_t waste = 0xFFFFFFFF;

	for(idx = 0; idx < linx->pool_num_lists; idx++) {
		if(size <= linx->pool_block_size[idx] &&
			waste > linx->pool_block_size[idx] - size) {
			bestfit = idx;
			waste = linx->pool_block_size[idx] - size;
		}
	}

	return bestfit;
}

static __inline
struct LINXSigAdm *sig_to_adm(const union LINX_SIGNAL *sig, const LINX *linx)
{
	int offset;
	if (is_pool_signal(linx, (const char *)sig))
		offset = linx->pool_signal_headroom;
	else
		offset = SIZEOF_SIGADM;

	return (struct LINXSigAdm *)(((char *)(sig)) - offset);
}

static __inline
union LINX_SIGNAL *adm_to_sig(const struct LINXSigAdm *adm, const LINX *linx)
{
	int offset;
	if (is_pool_signal(linx, (const char *)adm))
		offset = linx->pool_signal_headroom;
	else
		offset = SIZEOF_SIGADM;

	return (union LINX_SIGNAL *)(((char *)(adm)) + offset);
}

static void check_endmark(const LINX *linx, union LINX_SIGNAL **sigptr)
{
	union LINX_SIGNAL *sig;
	struct LINXSigAdm *sig_adm;

	sig = *sigptr;
	sig_adm = sig_to_adm(sig, linx);
	/* Always perform endmark check => don't use assert() */
	if (END_MARK != ((unsigned char *)sig)[sig_adm->sndrcv.size]) {
		fprintf(stderr, "Endmark overwritten for buffer %p\n",
			(void *)sig);
		abort();
	}
}				/* check_endmark */

#ifdef NDEBUG
#define check_linx(linx)
#else
static int check_linx(LINX * linx)
{
	assert(linx != NULL);
	assert(linx->magic == LINX_MAGIC);
	assert(linx->socket != -1);
	assert(linx->spid != 0);
	return 0;
}				/* check_linx */
#endif

#ifndef NDEBUG
static int check_buffer(LINX * linx, union LINX_SIGNAL **sigptr)
{
	struct LINXSigAdm *sig_adm;
	struct Link *link;

	assert(sigptr != NULL);
	assert(*sigptr != LINX_NIL);
	sig_adm = sig_to_adm(*sigptr, linx);
	assert(sig_adm->owner == linx);

	/* Verify that signal is in the list of owned signals */
	for (link = uint64_to_ptr(linx->owned_sig.next);
		 link != &linx->owned_sig; link = uint64_to_ptr(link->next)) {
		if (link == &sig_adm->link) {
			return 0;
		}
	}
	fprintf(stderr, "Buffer %p not recognized\n", (void *)sigptr);
	return -1;
}				/* check_buffer */
#endif

static __inline void link_sig_owner(LINX * linx, struct LINXSigAdm *sig_adm)
{
	struct Link *head;
	struct Link *next;
	struct Link *link;

	head = &linx->owned_sig;
	next = uint64_to_ptr(head->next);
	link = &sig_adm->link;

	assert(link != head);

	link->next = ptr_to_uint64(next);
	link->prev = ptr_to_uint64(head);
	next->prev = ptr_to_uint64(link);
	head->next = ptr_to_uint64(link);

	sig_adm->owner = ptr_to_uint64(linx);
}				/* link_sig_owner */

static __inline void unlink_sig_owner(struct LINXSigAdm *sig_adm)
{
	struct Link *link;
	struct Link *next;
	struct Link *prev;

	link = &sig_adm->link;
	next = uint64_to_ptr(link->next);
	prev = uint64_to_ptr(link->prev);

	next->prev = ptr_to_uint64(prev);
	prev->next = ptr_to_uint64(next);
#ifndef NDEBUG
	link->next = 0;
	link->prev = 0;
#endif
	sig_adm->owner = 0;
}				/* unlink_sig_owner */

static __inline void adm_free_buf(LINX * linx, struct LINXSigAdm *sig_adm)
{
	if (is_pool_signal(linx, (char *)sig_adm)) {
		struct linx_free_param free_param;
		free_param.offset = sig_adm->sndrcv.offset;
		ioctl(linx->socket, LINX_IOCTL_FREE, &free_param);
		return;
	}

	if (likely(sig_adm->true_size >= 0x400 && linx->free_buffer == NULL))
		linx->free_buffer = sig_adm;
	else
		free(sig_adm);
}				/* adm_free_buf */

static void free_owned_sigs(LINX * linx)
{
	struct Link *head = &linx->owned_sig;

	while (uint64_to_ptr(head->next) != head) {
		struct LINXSigAdm *sig_adm = uint64_to_ptr(head->next);
		unlink_sig_owner(sig_adm);
		adm_free_buf(linx, sig_adm);
	}
}				/* free_owned_sigs */

LINX *linx_open(const char *my_name, uint32_t options, void *arg)
{
	struct linx_huntname *huntname;
	LINX *linx;
	unsigned int module_version;
	unsigned int lib_major_version;
	int ret;
	struct linx_pool_info pool_info;
	struct linx_info recv_info;
	int idx;

	(void)options;		/* remove compiler warning */
	(void)arg;

	assert(offsetof(struct LINX_IPC, owned_sig) ==
		   offsetof(struct LINXSigAdm, link));
	assert(SIZEOF_SIGADM % 8 == 0);

	linx = malloc(sizeof(LINX));
	if (linx == NULL)
		goto fail_null;	/* errno from malloc */

	memset(linx, 0, sizeof(LINX));
#ifndef NDEBUG
	linx->magic = LINX_MAGIC;
#endif
	linx->owned_sig.next = ptr_to_uint64(&linx->owned_sig);
	linx->owned_sig.prev = ptr_to_uint64(&linx->owned_sig);
	linx->free_buffer = NULL;
	linx->socket = socket(AF_LINX, SOCK_DGRAM | SOCK_CLOEXEC, 0);
	if (linx->socket == -1) {
		goto fail_free;	/* errno from socket */
	}

	if (ioctl(linx->socket, LINX_IOCTL_VERSION, &module_version) < 0) {
		goto fail_close;	/* errno from ioctl */
	}

	lib_major_version = strtoul(LINX_VERSION, NULL, 0);
	/* krn mod major version = first 8 bits */
	if ((module_version >> 24) != lib_major_version) {
		/* The LINX kernel module was built with a different
		 * major version (linx_common.h) */
		fprintf(stderr, "LINX module version mismatch\n");
		errno = EINVAL;
		goto fail_close;
	}

	huntname = malloc(sizeof(struct linx_huntname) + strlen(my_name) + 1);
	if (huntname == NULL) {
		goto fail_close;	/* errno from malloc */
	}
	huntname->name = ((char *)huntname) + sizeof(struct linx_huntname);
	huntname->namelen = strlen(my_name);
	huntname->spid = 0;
	/* Associate my_name with socket so others can hunt for me */
	strcpy(huntname->name, my_name);
	if (ioctl(linx->socket, LINX_IOCTL_HUNTNAME, huntname) < 0) {
		free(huntname);
		goto fail_close;	/* errno from ioctl */
	}

	/* My SPID is returned, save it for later use */
	linx->spid = huntname->spid;
	free(huntname);

	assert(check_linx(linx) == 0);
	
	/* Get the linx_receive sigsize. */
	if (linx_recv_sigsize == 0) {
		recv_info.type = LINX_INFO_RECV_BUFFER_SIZE;
		recv_info.type_spec = &linx_recv_sigsize;
		if (unlikely(ioctl(linx->socket, LINX_IOCTL_INFO, &recv_info) == -1)) {
			linx_recv_sigsize = 0;
			goto fail_close;
		}
	}

	/* mmap the pool */
	ret = ioctl(linx->socket, LINX_IOCTL_POOL_INFO, &pool_info);
	if(ret == -1)
		goto fail_close;
	linx->pool_size = pool_info.size;
	linx->pool_signal_headroom = pool_info.headroom;
	linx->pool_offset = pool_info.offset;
	linx->pool_free_count = pool_info.s_free_count;
	linx->pool_num_lists = pool_info.num_lists;
	linx->pool_area = NULL;
	linx->pool_alloc_head = malloc(sizeof(uint32_t) * pool_info.num_lists);
	if (linx->pool_alloc_head == NULL) {
		goto fail_close;
	}
	linx->pool_block_size = malloc(sizeof(uint32_t) * pool_info.num_lists);
	if (linx->pool_block_size == NULL) {
		free(linx->pool_alloc_head);
		goto fail_close;
	}
	for (idx = 0; idx < pool_info.num_lists; idx++) {
		linx->pool_alloc_head[idx] = 0;
		linx->pool_block_size[idx] = pool_info.list[idx].block_size;
	}
	linx->pool_free_head = 0;

	if (linx->pool_size) {
#ifdef SHARE_VIRTUAL_POOL
			pthread_mutex_lock(&vp_mutex);
			if (poolUseCount == 0) 
			{
				linx->pool_area = mmap(0, pool_info.size + pool_info.offset,
						   PROT_READ|PROT_WRITE, MAP_SHARED, linx->socket, 0);
				if (linx->pool_area == (void *) -1) {
					printf("mmap failed with %s\n", strerror(errno));
					pthread_mutex_unlock(&vp_mutex);
					goto fail_free_close;
				}
				processPoolAreaP = linx->pool_area;
			}
			else
			{
				linx->pool_area = processPoolAreaP;
			}
			poolUseCount++;
			pthread_mutex_unlock(&vp_mutex);
#else
			linx->pool_area = mmap(0, pool_info.size + pool_info.offset,
									   PROT_READ|PROT_WRITE, MAP_SHARED, linx->socket, 0);

		if (linx->pool_area == (void *) -1) {
			printf("mmap failed with %s\n", strerror(errno));
			goto fail_free_close;
		}
#endif
		/* Adjust pool start according to the offset from the start of the page */
		linx->pool_area += linx->pool_offset;
	}

	return linx;

fail_free_close:
	free(linx->pool_alloc_head);
	free(linx->pool_block_size);
fail_close:
	(void)close(linx->socket);
fail_free:
	free(linx);
fail_null:
	return NULL;
}				/* linx_open */

int linx_close(LINX * linx)
{
	assert(check_linx(linx) == 0);
	free_owned_sigs(linx);
	if (linx->free_buffer != NULL) {
		free(linx->free_buffer);
	}
	
	if (linx->pool_size) {
		linx->pool_area -= linx->pool_offset;
#ifdef SHARE_VIRTUAL_POOL
		pthread_mutex_lock(&vp_mutex);
		poolUseCount--;
		if (poolUseCount == 0) {
			munmap(linx->pool_area, linx->pool_size + linx->pool_offset);
		}
		pthread_mutex_unlock(&vp_mutex);
#else
		munmap(linx->pool_area, linx->pool_size + linx->pool_offset);
#endif
	}

	(void)close(linx->socket);
#ifndef NDEBUG
	linx->socket = -1;
	linx->magic = 0;
	linx->free_buffer = NULL;
	/* At kernel level, the pool blocks in pool_free_head list were still
	 * owned by this endpoint, so it's safe to set pool_free_head to 0.
	 * The blocks were previously freed on
	 * close()->linx_release()->free_mem_by_owner() path.
	 */
	linx->pool_free_head = 0;
	linx->free_list_size = 0;
#endif
	free(linx->pool_alloc_head);
	free(linx->pool_block_size);
	free(linx);
	return 0;
}				/* linx_close */

static int
hunt_common(LINX * linx, const char *name, union LINX_SIGNAL **hunt_sig,
		LINX_SPID from)
{
	struct LINXSigAdm *sig_adm = NULL;
	struct linx_hunt_param *hunt_param = NULL;
	int namelen;
	int status = -1;

	namelen = strlen(name);

	hunt_param = malloc(sizeof(struct linx_hunt_param) + namelen + 1);

	if (hunt_param == NULL) {
		return status;
	}

	if (hunt_sig != NULL) {
		assert(check_buffer(linx, hunt_sig) == 0);
		sig_adm = sig_to_adm(*hunt_sig, linx);
		check_endmark(linx, hunt_sig);

		if (is_pool_signal(linx, *(char **)hunt_sig)) {
			hunt_param->sig = (uintptr_t)NULL;
			hunt_param->offset = sig_adm->sndrcv.offset;
		} else {
			hunt_param->sig = (uintptr_t)*hunt_sig;
			hunt_param->offset = 0;
		}
		hunt_param->sigsize = sig_adm->sndrcv.size;

		*hunt_sig = LINX_NIL;
	} else {
		hunt_param->sig = (uintptr_t)NULL;
		hunt_param->sigsize = 0;
		hunt_param->offset = 0;
	}

	hunt_param->from = from;
	hunt_param->name = (uintptr_t)hunt_param +
		sizeof(struct linx_hunt_param);
	strcpy(((char *)((uintptr_t)hunt_param +
			 sizeof(struct linx_hunt_param))), name);
	hunt_param->namelen = namelen;

	if (ioctl(linx->socket, LINX_IOCTL_HUNT, hunt_param) != -1) {
		status = 0;
	}
	free(hunt_param);

	if (sig_adm != NULL) {
		unlink_sig_owner(sig_adm);
		if(!is_pool_signal(linx, (char *)sig_adm))
			adm_free_buf(linx, sig_adm);
	}
	if (hunt_sig != NULL && *hunt_sig != LINX_NIL)
		(void)linx_free_buf(linx, hunt_sig);

	return status;
}				/* hunt_common */

int
linx_hunt_from(LINX * linx,
		   const char *name, union LINX_SIGNAL **hunt_sig, LINX_SPID from)
{
	assert(check_linx(linx) == 0);
	/* Check of linx moved here because of linx->spid in linx_hunt */
	return hunt_common(linx, name, hunt_sig, from);
}				/* linx_hunt */

int linx_hunt(LINX * linx, const char *name, union LINX_SIGNAL **hunt_sig)
{
	assert(check_linx(linx) == 0);
	/* Check of linx moved here because of linx->spid */
	return hunt_common(linx, name, hunt_sig, linx->spid);
}				/* linx_hunt */

LINX_OSATTREF
linx_attach(LINX * linx, union LINX_SIGNAL ** sig_ptr, LINX_SPID spid)
{
	struct linx_attach_param attach_param;
	struct LINXSigAdm *sig_adm = NULL;
	LINX_OSATTREF attref = LINX_ILLEGAL_ATTREF;

	assert(check_linx(linx) == 0);

	if (sig_ptr != NULL) {
		assert(check_buffer(linx, sig_ptr) == 0);
		sig_adm = sig_to_adm(*sig_ptr, linx);
		check_endmark(linx, sig_ptr);

		if (is_pool_signal(linx, *(char **)sig_ptr)) {
			attach_param.sig = (uintptr_t)NULL;
			attach_param.offset = sig_adm->sndrcv.offset;
		} else {
			attach_param.sig = (uintptr_t)*sig_ptr;
			attach_param.offset = 0;
		}
		attach_param.sigsize = sig_adm->sndrcv.size;

		*sig_ptr = LINX_NIL;
	} else {
		attach_param.sig = (uintptr_t)NULL;
		attach_param.sigsize = 0;
		attach_param.offset = 0;
	}

	attach_param.attref = LINX_ILLEGAL_ATTREF;
	attach_param.spid = spid;
	if (ioctl(linx->socket, LINX_IOCTL_ATTACH, &attach_param) != -1) {
		attref = attach_param.attref;
	}
	if (sig_adm != NULL) {
		unlink_sig_owner(sig_adm);
		if(!is_pool_signal(linx, (char *)sig_adm))
			adm_free_buf(linx, sig_adm);
	}
	return attref;
}

int linx_detach(LINX * linx, LINX_OSATTREF * attref_ptr)
{
	struct linx_detach_param detach_param;

	assert(check_linx(linx) == 0);

	detach_param.attref = *attref_ptr;
	*attref_ptr = LINX_ILLEGAL_ATTREF;

	if (ioctl(linx->socket, LINX_IOCTL_DETACH, &detach_param) == -1) {
		return -1;
	}

	return 0;
}

union LINX_SIGNAL *linx_alloc(LINX * linx, LINX_OSBUFSIZE size,
				  LINX_SIGSELECT sig_no)
{
	size_t need;
	struct LINXSigAdm *sig_adm;
	union LINX_SIGNAL *sig;

	assert(check_linx(linx) == 0);

	if (unlikely(size < sizeof(LINX_SIGSELECT))) {
		errno = EMSGSIZE;
		return LINX_NIL;
	}

	if ((sig_adm = linx->free_buffer) != NULL &&
		sig_adm->true_size >= size) {
		linx->free_buffer = NULL;
		goto ok;
	}

	need = SIZEOF_SIGADM + size + 1; /* +1 For the endmark. */

	sig_adm = malloc(need);
	if (unlikely(sig_adm == NULL)) {
		return LINX_NIL;
	}
	sig_adm->true_size = size;
	  ok:
	sig_adm->sndrcv.size = size;
	sig_adm->sndrcv.from = linx->spid;
	sig_adm->sndrcv.to = linx->spid;
	sig_adm->sndrcv.sig_attr = 0;
	sig_adm->sndrcv.tmo = ~0;

	sig = adm_to_sig(sig_adm, linx);
	sig->sig_no = sig_no;
	*((unsigned char *)sig + size) = END_MARK;
	sig_adm->sndrcv.buffer = (uintptr_t)sig;
	sig_adm->sndrcv.real_buf = (uintptr_t)sig;

	link_sig_owner(linx, sig_adm);

	assert(check_buffer(linx, &sig) == 0);
	return sig;
}				/* linx_alloc */

union LINX_SIGNAL *linx_s_alloc(LINX * linx, LINX_OSBUFSIZE size,
				LINX_SIGSELECT sig_no, uint32_t flags)
{
	size_t need;
	struct LINXSigAdm *sig_adm;
	union LINX_SIGNAL *sig;
	int idx;

	struct linx_alloc_param alloc_param;

	if (linx->pool_size == 0) {
		errno = EOPNOTSUPP;
		return LINX_NIL;
	}

	/* flags does not do anything new for now. shall allocate a signal from
	   the shared pool. */
	if(flags != 0) {
		errno = EINVAL;
		return LINX_NIL;
	}

	assert(check_linx(linx) == 0);

	if (unlikely(size < sizeof(LINX_SIGSELECT))) {
		errno = EMSGSIZE;
		return LINX_NIL;
	}

	/* when allocating a signal from the pool, the sigadm is added by the */
	/*	pool */
	need = size + 1; /* +1 For the endmark. */

	/* Find the list index. */
	idx = find_block_list(linx, need);
	if (unlikely(idx < 0 || idx >= linx->pool_num_lists)) {
		errno = EMSGSIZE;
		return LINX_NIL;
	}

	if (linx->pool_alloc_head[idx] == 0) {
		alloc_param.size = need;
		alloc_param.offset = 0;
		if (ioctl(linx->socket, LINX_IOCTL_ALLOC, &alloc_param) == -1) {
			return LINX_NIL;
		}

		sig = (union LINX_SIGNAL *)(linx->pool_area + alloc_param.offset);
		sig_adm = sig_to_adm(sig, linx);
		sig_adm->sndrcv.offset = alloc_param.offset;
		
	} else {
		sig = (union LINX_SIGNAL *)(linx->pool_area + linx->pool_alloc_head[idx]);
		sig_adm = sig_to_adm(sig, linx);
		sig_adm->sndrcv.offset = linx->pool_alloc_head[idx];
	}

	linx->pool_alloc_head[idx] = sig_adm->sndrcv.next_sig_offset;

	sig->sig_no = sig_no;
	*((unsigned char *)sig + size) = END_MARK;
	
	/* true_size is set in the kernel. */ 
	sig_adm->sndrcv.size = size;
	sig_adm->sndrcv.from = linx->spid;
	sig_adm->sndrcv.to = linx->spid;
	sig_adm->sndrcv.sig_attr = 0;
	sig_adm->sndrcv.tmo = ~0;

	sig_adm->sndrcv.buffer = 0;

	link_sig_owner(linx, sig_adm);

	assert(check_buffer(linx, &sig) == 0);
	return sig;
}				/* linx_s_alloc */


int linx_free_buf(LINX * linx, union LINX_SIGNAL **sig)
{
	struct LINXSigAdm *sig_adm;

	assert(check_linx(linx) == 0);

	assert(check_buffer(linx, sig) == 0);
	sig_adm = sig_to_adm(*sig, linx);
	check_endmark(linx, sig);
	unlink_sig_owner(sig_adm);
	if (is_pool_signal(linx, (char *)sig_adm)) {
		sig_adm->sndrcv.next_sig_offset = linx->pool_free_head;
		if (++linx->free_list_size == linx->pool_free_count) {
			adm_free_buf(linx, sig_adm);
			linx->pool_free_head = 0;
			linx->free_list_size = 0;
		} else {
			linx->pool_free_head = sig_adm->sndrcv.offset;
		}
		
	} else {	
		adm_free_buf(linx, sig_adm);
	}
	/* Take signal pointer from user. */
	*sig = LINX_NIL;

	return 0;
}				/* linx_free_buf */

LINX_OSBUFSIZE linx_sigsize(LINX * linx, union LINX_SIGNAL ** sig)
{
	struct LINXSigAdm *sig_adm;

	assert(check_linx(linx) == 0);

	assert(check_buffer(linx, sig) == 0);
	sig_adm = sig_to_adm(*sig, linx);
	check_endmark(linx, sig);

	return sig_adm->sndrcv.size;
}				/* linx_sigsize */

static int
resize_signal(LINX * linx, union LINX_SIGNAL **sig_ptr, LINX_OSBUFSIZE newsize)
{
	struct LINXSigAdm *sig_adm;

	assert(check_buffer(linx, sig_ptr) == 0);
	sig_adm = sig_to_adm(*sig_ptr, linx);
	check_endmark(linx, sig_ptr);

	/* Check if we need to allocate a larger buffer */
	if (newsize < sig_adm->true_size)
		goto update_endmark;

	if (is_pool_signal(linx, (char *)sig_adm)) {
		union LINX_SIGNAL *new_sig;
		size_t need;

		need = newsize + 1;
		new_sig = linx_s_alloc(linx, need, (*sig_ptr)->sig_no, 0);
		memcpy(new_sig, *sig_ptr, sig_adm->sndrcv.size);
		linx_free_buf(linx, sig_ptr);
		*sig_ptr = new_sig;
		sig_adm = sig_to_adm(*sig_ptr, linx);
	} else {
		/* + 1 For the endmark. */
		size_t need = SIZEOF_SIGADM + newsize + 1;
		unlink_sig_owner(sig_adm);
		sig_adm = realloc(sig_adm, need);
		if (sig_adm == NULL) {
			/* *sig_ptr still points to original signal */
			assert(check_buffer(linx, sig_ptr) == 0);
			link_sig_owner(linx, sig_to_adm(*sig_ptr, linx));
			return -1;
		}
		/* Since the realloc() succeeded, we need to update the true
		   size of the buffer */
		sig_adm->true_size = newsize;
		/* Return potentially new signal pointer to caller */
		*sig_ptr = adm_to_sig(sig_adm, linx);
		sig_adm->sndrcv.buffer = (uintptr_t)(*sig_ptr);
		sig_adm->sndrcv.real_buf = (uintptr_t)(*sig_ptr);
		link_sig_owner(linx, sig_adm);
		assert(check_buffer(linx, sig_ptr) == 0);
	}

update_endmark:
	sig_adm->sndrcv.size = newsize;
	((unsigned char *)(*sig_ptr))[newsize] = END_MARK;
	assert(check_buffer(linx, sig_ptr) == 0);
	assert(sig_to_adm(*sig_ptr, linx) == sig_adm);

	return 0;
}				/* resize_signal */

int
linx_set_sigsize(LINX * linx, union LINX_SIGNAL **sig, LINX_OSBUFSIZE newsize)
{
	assert(check_linx(linx) == 0);

	if (newsize < (LINX_OSBUFSIZE) sizeof(LINX_SIGSELECT)) {
		errno = EMSGSIZE;
		return -1;
	}

	return resize_signal(linx, sig, newsize);
}

LINX_SPID linx_sender(LINX * linx, union LINX_SIGNAL ** sig)
{
	struct LINXSigAdm *sig_adm;

	assert(check_linx(linx) == 0);

	assert(check_buffer(linx, sig) == 0);
	sig_adm = sig_to_adm(*sig, linx);
	check_endmark(linx, sig);

	return sig_adm->sndrcv.from;
}				/* linx_sender */

int linx_send(LINX * linx, union LINX_SIGNAL **sig, LINX_SPID to)
{
	struct LINXSigAdm *sig_adm;
	int ret;
	struct linx_sndrcv_param sndrcv;

	assert(check_linx(linx) == 0);
	sig_adm = sig_to_adm(*sig, linx);

	if (linx != uint64_to_ptr(sig_adm->owner)) {
		LINX *real_owner = uint64_to_ptr(sig_adm->owner);

		/* Always consumes the signal buffer, even if the call fails. */
		unlink_sig_owner(sig_adm);
		adm_free_buf(real_owner, sig_adm);

		errno = EINVAL;
		ret = -1;
		goto out;
	}
	check_endmark(linx, sig);

	sig_adm->sndrcv.to = to;
	sig_adm->sndrcv.from = linx->spid;
	sig_adm->sndrcv.sig_attr = 0;

	sndrcv = sig_adm->sndrcv;
	/* ioctl() returns zero on success */
	unlink_sig_owner(sig_adm);
	ret = ioctl(linx->socket, LINX_IOCTL_SEND, &sndrcv);

	if (ret == 0) {
		sig_adm->sndrcv = sndrcv;
	}
	if (ret != 1) {
		/* Don't free signals sent to back to itself, they are needed later! */
		adm_free_buf(linx, sig_adm);
	}
out:
	/* Take signal pointer from user.
	   As per the manual page this is always done. */
	*sig = LINX_NIL;

	return ret == 1 ? 0 : ret;
}

int linx_send_w_s(LINX * linx, union LINX_SIGNAL **sig,
		  LINX_SPID from, LINX_SPID to)
{
	struct LINXSigAdm *sig_adm;
	int ret;
	struct linx_sndrcv_param sndrcv;

	assert(check_linx(linx) == 0);

	sig_adm = sig_to_adm(*sig, linx);
	check_endmark(linx, sig);

	if (linx != uint64_to_ptr(sig_adm->owner)) {
		LINX *real_owner = uint64_to_ptr(sig_adm->owner);

		/* Always consumes the signal buffer, even if the call fails. */
		unlink_sig_owner(sig_adm);
		adm_free_buf(real_owner, sig_adm);

		errno = EINVAL;
		ret = -1;
		goto out;
	}

	sig_adm->sndrcv.to = to;
	sig_adm->sndrcv.from = from;
	sig_adm->sndrcv.sig_attr = 0;

	sndrcv = sig_adm->sndrcv;

	/* ioctl() returns zero on success */
	unlink_sig_owner(sig_adm);
	ret = ioctl(linx->socket, LINX_IOCTL_SEND, &sndrcv);

	if (ret == 0) {
		sig_adm->sndrcv = sndrcv;
	}

	if (ret != 1) {
		/* Don't free signals sent to back to itself, they are needed later! */
		adm_free_buf(linx, sig_adm);
	}

out:
	/* Take signal pointer from user. */
	*sig = LINX_NIL;

	return ret == 1 ? 0 : ret;
}

int linx_send_w_opt(LINX * linx, union LINX_SIGNAL **sig, LINX_SPID from,
			LINX_SPID to, int32_t *taglist)
{
	struct LINXSigAdm *sig_adm;
	int i = 0;
	int ret;
	struct linx_sndrcv_param sndrcv;

	assert(check_linx(linx) == 0);

	sig_adm = sig_to_adm(*sig, linx);
	check_endmark(linx, sig);

	if (linx != uint64_to_ptr(sig_adm->owner)) {
		LINX *real_owner = uint64_to_ptr(sig_adm->owner);

		/* consume the signal */
		unlink_sig_owner(sig_adm);
		adm_free_buf(real_owner, sig_adm);

		errno = EINVAL;
		ret = -1;
		goto out;
	}

	sig_adm->sndrcv.to = to;
	sig_adm->sndrcv.from = from;
	sig_adm->sndrcv.sig_attr = 0;

	if (unlikely(taglist != NULL)) {
		while(taglist[i] != LINX_SIG_OPT_END) {
			/* taglist will currenty be of max 3 items */
			if(i > 2) {
				errno = -EINVAL;
				break;
			}
			if(taglist[i] == LINX_SIG_OPT_OOB)
				if(taglist[i + 1] == 1)
					sig_adm->sndrcv.sig_attr |= MSG_OOB;
			taglist += 2;
		}
	}

	sndrcv = sig_adm->sndrcv;

	/* ioctl() returns zero on success */
	unlink_sig_owner(sig_adm);
	ret = ioctl(linx->socket, LINX_IOCTL_SEND, &sndrcv);

	if (ret == 0) {
		sig_adm->sndrcv = sndrcv;
	}

	if (ret != 1) {
		/* Don't free signals sent to back to itself, they are needed later! */
		adm_free_buf(linx, sig_adm);
	}

out:
	/* Take signal pointer from user. */
	*sig = LINX_NIL;

	return ret == 1 ? 0 : ret;
}

int
linx_sigattr(const LINX *linx, const union LINX_SIGNAL **sig,
		 uint32_t attr, void **value)
{
	struct LINXSigAdm *sig_adm = sig_to_adm(*sig, linx);

	check_endmark(linx, (union LINX_SIGNAL **)sig);

	switch(attr) {
	case LINX_SIG_ATTR_OOB:
	{
		uint8_t *ret = (uint8_t *)value;
		if(sig_adm->sndrcv.sig_attr & LINX_SIG_ATTR_OOB)
			*ret = 1;
		else
			*ret = ~0;
		return 0;
	}
	default:
		errno = EINVAL;
		return -1;
	}
}

static int
common_receive(LINX * linx, union LINX_SIGNAL **sig_ptr,
		   const LINX_SIGSELECT * sig_sel, LINX_OSBOOLEAN tmo_used,
		   LINX_OSTIME tmo, LINX_SPID from)
{
	LINX_OSBUFSIZE sigsize;
	struct LINXSigAdm *sig_adm;
	union LINX_SIGNAL *sig;

	assert(check_linx(linx) == 0);

	/* Alloc a default sized buffer */
	if (unlikely((sig = linx_alloc(linx, linx_recv_sigsize, 0))
			 == LINX_NIL)) {
		/* errno from malloc() */
		goto common_receive_failed;
	}

	sig_adm = sig_to_adm(sig, linx);
	sig_adm->sndrcv.sigselect_size = (sig_sel == 0) ? 0 :
		sizeof(LINX_SIGSELECT) * (abs((int32_t) sig_sel[0]) + 1);
	sig_adm->sndrcv.sigselect = (uintptr_t)(sig_sel);
	sig_adm->sndrcv.from = from;

	/* linx_receive_w_tmo */
	if (unlikely(tmo_used)) {
		sig_adm->sndrcv.tmo = tmo;
	} else {
		sig_adm->sndrcv.tmo = ~0;
	}

	for (;;) {
		ssize_t read_size;
		read_size = ioctl(linx->socket, LINX_IOCTL_RECEIVE,
				  &sig_adm->sndrcv);
		if (likely(read_size > 0)) {
			sigsize = read_size;
			break;
		}

		sigsize = ((uint32_t *)
			   ((uintptr_t)(sig_adm->sndrcv.buffer)))[0];

		if (sig_adm->sndrcv.tmo == 0 && sigsize == 0) {
			/* Timeout */
			*sig_ptr = adm_to_sig(sig_adm, linx);
			(void)linx_free_buf(linx, sig_ptr);
			*sig_ptr = LINX_NIL;
			return 0;
		} else if (read_size == 0) {
			/* The size of the signal did not fit into the receive
			 * buffer, resize it and receive again */
			*sig_ptr = adm_to_sig(sig_adm, linx);
			if (resize_signal(linx, sig_ptr, sigsize) < 0) {
				/* errno from realloc() */
				goto common_receive_failed_free_buf;
			}
			sig_adm = sig_to_adm(*sig_ptr, linx);
		} else if (errno != EINTR) {
			*sig_ptr = adm_to_sig(sig_adm, linx);
			goto common_receive_failed_free_buf;
		}
	}

	if(sig_adm->sndrcv.buffer == 0 && linx->pool_size) {
		/* pool signal */
		union LINX_SIGNAL *psig;
		struct LINXSigAdm *adm;

		psig = (union LINX_SIGNAL *)
			(linx->pool_area + sig_adm->sndrcv.offset);
		adm = sig_to_adm(psig, linx);
		memcpy(&adm->sndrcv, &sig_adm->sndrcv, sizeof(sig_adm->sndrcv));
		/* Set true_size in sig_adm area */
		adm->true_size = sig_adm->sndrcv.real_size;
		*sig_ptr = psig;
		/* free the temporary signal */
		unlink_sig_owner(sig_adm);
		adm_free_buf(linx, sig_adm);

		link_sig_owner(linx, adm);
	} else if (sig_adm->sndrcv.real_buf != sig_adm->sndrcv.buffer) {
		union LINX_SIGNAL *sig;
		struct LINXSigAdm *adm;

		sig = (void *)(uintptr_t)sig_adm->sndrcv.real_buf;
		adm = sig_to_adm(sig, linx);
		adm->sndrcv = sig_adm->sndrcv;
		adm->sndrcv.buffer = (uintptr_t)sig;
		unlink_sig_owner(sig_adm);
		adm_free_buf(linx, sig_adm);
		*sig_ptr = sig;
		sig_adm = adm;

		link_sig_owner(linx, sig_adm);
		assert(sigsize <= sig_adm->true_size);
	} else {
		assert(sigsize <= sig_adm->true_size);
		*sig_ptr = adm_to_sig(sig_adm, linx);
		((unsigned char *)*sig_ptr)[sigsize] = END_MARK;
	}

	return sigsize;

 common_receive_failed_free_buf:
	(void)linx_free_buf(linx, sig_ptr);
 common_receive_failed:
	*sig_ptr = LINX_NIL;
	return -1;
}

int
linx_receive(LINX * linx, union LINX_SIGNAL **sig,
		 const LINX_SIGSELECT * sig_sel)
{
	/* Input parameters are checked in common_receive. */
	return common_receive(linx, sig, sig_sel, LINX_FALSE, 0,
				  LINX_ILLEGAL_SPID);
}

int
linx_receive_w_tmo(LINX * linx, union LINX_SIGNAL **sig,
		   LINX_OSTIME tmo, const LINX_SIGSELECT * sig_sel)
{
	/* Input parameters are checked in common_receive. */
	return common_receive(linx, sig, sig_sel, LINX_TRUE, tmo,
				  LINX_ILLEGAL_SPID);
}

int
linx_receive_from(LINX * linx, union LINX_SIGNAL **sig,
		  LINX_OSTIME tmo, const LINX_SIGSELECT * sig_sel,
		  LINX_SPID from)
{
	/* Input parameters are checked in common_receive. */
	return common_receive(linx, sig, sig_sel, LINX_TRUE, tmo, from);
}

int linx_get_descriptor(LINX * linx)
{
	assert(check_linx(linx) == 0);

	return linx->socket;
}

LINX_SPID linx_get_spid(LINX * linx)
{
	assert(check_linx(linx) == 0);

	return linx->spid;
}

int linx_get_name(LINX * linx, LINX_SPID spid, char **name)
{
	struct linx_info info;
	struct linx_info_name iname;
	int namelen;
	char *buf = NULL;

	assert(check_linx(linx) == 0);

	*name = NULL;

	iname.name = NULL;
	iname.namelen = 0;
	iname.spid = spid;
	info.type = LINX_INFO_NAME;
	info.type_spec = &iname;

	/* Get the length of the name */
	namelen = ioctl(linx->socket, LINX_IOCTL_INFO, &info);
	if (unlikely(namelen == -1)) {
		return -1;	/* errno from ioctl() */
	}

	buf = malloc(namelen);
	if (unlikely(buf == NULL)) {
		return -1;
	}

	iname.name = buf;
	iname.namelen = namelen;
	iname.spid = spid;
	info.type = LINX_INFO_NAME;
	info.type_spec = &iname;

	/* Get name */
	if (unlikely(ioctl(linx->socket, LINX_IOCTL_INFO, &info) == -1)) {
		/* errno from ioctl() */
		free(buf);
		return -1;
	}

	*name = buf;

	return 0;
}

int linx_free_name(LINX * linx, char **name)
{
	assert(check_linx(linx) == 0);

	if (name == NULL) {
		errno = EINVAL;
		return -1;
	}

	if (*name != NULL)
		free(*name);

	*name = NULL;

	return 0;
}

pid_t linx_get_owner(LINX * linx, LINX_SPID spid)
{
	struct linx_info info;
	struct linx_info_owner owner;

	assert(check_linx(linx) == 0);

	info.type = LINX_INFO_OWNER;
	info.type_spec = &owner;
	owner.spid = spid;
	if (unlikely(ioctl(linx->socket, LINX_IOCTL_INFO, &info) == -1)) {
		return -1;
	}

	return owner.owner;
}

int linx_get_stat(LINX * linx, LINX_SPID spid, struct linx_info_stat **stat)
{
	struct linx_info info;
	struct linx_info_stat *istat;

	*stat = NULL;

	assert(check_linx(linx) == 0);

	istat = malloc(sizeof(struct linx_info_stat));
	if (unlikely(istat == NULL)) {
		return -1;
	}

	istat->spid = spid;
	info.type = LINX_INFO_STAT;
	info.type_spec = istat;

	/* Get the statistics from the SPID */
	if (unlikely(ioctl(linx->socket, LINX_IOCTL_INFO, &info) == -1)) {
		free(istat);
		return -1;
	}

	*stat = istat;

	return 0;
}

int linx_free_stat(LINX * linx, struct linx_info_stat **stat)
{
	assert(check_linx(linx) == 0);

	if (stat == NULL) {
		errno = EINVAL;
		return -1;
	}

	if (*stat != NULL)
		free(*stat);

	*stat = NULL;

	return 0;
}

LINX_OSTMOREF
linx_request_tmo(LINX * linx, LINX_OSTIME tmo, union LINX_SIGNAL ** sig)
{
	struct linx_tmo_param tmo_param;
	struct LINXSigAdm *sig_adm = NULL;
	LINX_OSTMOREF tmoref = LINX_ILLEGAL_TMOREF;

	assert(check_linx(linx) == 0);

	if (sig != NULL) {
		assert(check_buffer(linx, sig) == 0);
		sig_adm = sig_to_adm(*sig, linx);
		check_endmark(linx, sig);

		if (is_pool_signal(linx, *(char **)sig)) {
			tmo_param.sig = (uintptr_t)NULL;
			tmo_param.offset = sig_adm->sndrcv.offset;
		} else {
			tmo_param.sig = (uintptr_t)*sig;
			tmo_param.offset = 0;
		}
		tmo_param.sigsize = sig_adm->sndrcv.size;

		*sig = LINX_NIL;
	} else {
		tmo_param.sig = (uintptr_t)NULL;
		tmo_param.sigsize = 0;
		tmo_param.offset = 0;
	}

	tmo_param.tmoref = LINX_ILLEGAL_TMOREF;
	tmo_param.tmo = tmo;
	if (ioctl(linx->socket, LINX_IOCTL_REQUEST_TMO, &tmo_param) != -1) {
		tmoref = tmo_param.tmoref;
	}
	if (sig_adm != NULL) {
		unlink_sig_owner(sig_adm);
		if(!is_pool_signal(linx, (char *)sig_adm))
			adm_free_buf(linx, sig_adm);
	}
	return tmoref;
}

int linx_cancel_tmo(LINX * linx, LINX_OSTMOREF * tmoref)
{
	struct linx_tmo_param tmo_param;

	assert(check_linx(linx) == 0);

	tmo_param.tmoref = *tmoref;
	*tmoref = LINX_ILLEGAL_TMOREF;

	if (ioctl(linx->socket, LINX_IOCTL_CANCEL_TMO, &tmo_param) == -1) {
		return -1;
	}

	return 0;
}

int linx_modify_tmo(LINX * linx, LINX_OSTMOREF * tmoref, LINX_OSTIME tmo)
{
	struct linx_tmo_param tmo_param;

	assert(check_linx(linx) == 0);

	tmo_param.tmoref = *tmoref;
	tmo_param.tmo = tmo;
	if (ioctl(linx->socket, LINX_IOCTL_MODIFY_TMO, &tmo_param) == -1) {
		*tmoref = LINX_ILLEGAL_TMOREF;
		return -1;
	}
	return 0;
}

LINX_NLREF linx_request_new_link(LINX * linx, LINX_NLTOKEN token)
{
	struct linx_new_link_param new_link;

	assert(check_linx(linx) == 0);

	new_link.token = token;
	if (ioctl(linx->socket, LINX_IOCTL_REQUEST_NEW_LINK, &new_link) == -1) {
		return 0;
	}
	return new_link.new_link_ref;
}

int linx_cancel_new_link(LINX * linx, LINX_NLREF * new_link_ref)
{
	struct linx_new_link_param new_link;

	assert(check_linx(linx) == 0);

	new_link.new_link_ref = *new_link_ref;
	*new_link_ref = 0;
	return ioctl(linx->socket, LINX_IOCTL_CANCEL_NEW_LINK, &new_link);
}

int linx_get_version(char *buf)
{
		int s;
		unsigned int v;

		s = socket(AF_LINX, SOCK_DGRAM | SOCK_CLOEXEC, 0);
	if (s == -1)
				return -1;
	if (ioctl(s, LINX_IOCTL_VERSION, &v) == -1) {
				close(s);
				return -1;
	}
		close(s);

		/* Note: buf must contain at least 14 bytes. */
		if (buf != NULL)
				sprintf(buf, "%u.%u.%u", v >> 24, (v >> 8) & 0xffff, v & 0xff);

		/*
		 * Version: b31-b24 => major version.
		 *			b23-b8	=> minor version.
		 *			b8-b0	=> patch version.
		 */
		return v; /* 255.65535.255 is equal to -1, but we aren't there yet. */
}
