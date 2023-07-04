/*
 * Copyright (C) 2006-2019 by Enea Software AB.
 * All rights reserved.
 *
 * This Example is furnished under a Software License Agreement and
 * may be used only in accordance with the terms of such agreement.
 * No title to and ownership of the Example is hereby transferred.
 *
 * The information in this Example is subject to change
 * without notice and should not be construed as a commitment
 * by Enea Software AB.
 *
 * DISCLAIMER
 * This Example is delivered "AS IS", consequently
 * Enea Software AB makes no representations or warranties,
 * expressed or implied, for the Example.
 */

#include <stdio.h>
#include <sys/types.h>
#include <sys/time.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>

#include <linx.h>
#include <linx_types.h>
#include <linx_socket.h>

#include "linx_bmark.h"

extern pid_t gettid(void);

/****************************************/

union LINX_SIGNAL
{
	LINX_SIGSELECT sigNo;
};

/****************************************/

static long
test_once(LINX *linx, LINX_SPID server, int use_linx_api, int use_pthreads,
         int use_linx_s_alloc)
{

	union LINX_SIGNAL *sig;
	struct timeval tv = { 0, 0};
	LINX_SPID test_slave;
	static const LINX_SIGSELECT any_sig[] = { 0 };
	long clk;
	static char buf[65536];	/* buffer used when not using linx api. */

	test_slave = create_test_slave(linx, server, use_linx_api,
				                      use_pthreads, use_linx_s_alloc);

	/* We do not use default LINX_OS_ATTACH_SIG */
	if (use_linx_s_alloc == 1)
   {
      sig = linx_s_alloc(linx, ATTACH_SIG_SIZE, ATTACH_TEST_SIG, 0);
   }
   else
   {
      sig = linx_alloc(linx, ATTACH_SIG_SIZE, ATTACH_TEST_SIG);
   }
	linx_attach(linx, &sig, test_slave);

	if (use_linx_api)
   {
      /* This will never come back;
       * waiting only the effect of it (attach in this case) */
		if (use_linx_s_alloc == 1)
      {
         sig = linx_s_alloc(linx, ATTACH_SIG_SIZE, ATTACH_TEST_REQ, 0);
      }
      else
      {
         sig = linx_alloc(linx, ATTACH_SIG_SIZE, ATTACH_TEST_REQ);
      }

      /* Start timer. */
      get_time(&tv);

      /*
		 * Send ATTACH_TEST_REQ to test slave to close its endpoint
		 * in order to trigger the attach signal.
		 */
		linx_send(linx, &sig, test_slave);

      /*
		 * Receive the attach signal.
		 * Assume we received the correct signal here for measuring
		 * purposes!
		 */
		linx_receive(linx, &sig, any_sig);

		/* Assume we received the correct signal here for measuring
		 * purposes! */
		get_time(&tv);

      /* Stop timer. */
		clk = get_time(&tv);

		if (sig->sigNo != ATTACH_TEST_SIG)
      {
			ERR("Wrong signal received in attachtest %ud",
			    sig->sigNo);
		}

		PRINT(DBG, "Response time: %ld us\n", clk);

		linx_free_buf(linx, &sig);
	}
   else
   {
		int len;
		struct sockaddr_linx to;
		socklen_t socklen;
		int sd = linx_get_descriptor(linx);
		sig = (void *)buf;
		socklen = sizeof(struct sockaddr_linx);

		to.family = AF_LINX;
		to.spid = test_slave;

      /* This will never come back;
       * waiting only the effect of it (attach in this case) */
		sig->sigNo = ATTACH_TEST_REQ;

      /* Start timer. */
      get_time(&tv);

		len = sendto(sd, sig, ATTACH_SIG_SIZE, 0,
			          (void *)&to, socklen);

		if (unlikely((size_t)len != ATTACH_SIG_SIZE))
      {
			ERR("sendto returned: %d when asked for: %d",
			    len, ATTACH_SIG_SIZE);
		}

		if (unlikely(len <= 0))
      {
			ERR("Failed to send the ATTACH_SEND_REQ signal "
			    "(%d, %s)\n", len, strerror(errno));
		}

		len = recvfrom(sd, sig, ATTACH_SIG_SIZE,
			            0, (void *)&to, &socklen);

		if (unlikely(len <= 0))
      {
			ERR("Failed to receive a ATTACH_TEST_REQ signal "
			    "(%d, %d)\n", len, errno);
		}

      /* Stop timer. */
		get_time(&tv);

		clk = get_time(&tv);

		PRINT(DBG, "Response time: %ld us\n", clk);
	}

	return clk;
}

/****************************************/

int
attach_test(LINX * linx, const char *path,
	         int cnt, LINX_SPID server,
            int use_linx_api, int use_pthreads,
            int use_linx_s_alloc)
{

	long ack = 0;
	int i;
	long max = 0;
    long min = LONG_MAX;
    float mean;
    char buf[128];
    FILE *of;

	printf("\n%%%% Running attach test %s linx api %%%%\n",
	       use_linx_api ? "with" : "without");
   printf("%s", use_linx_api && use_linx_s_alloc ? "Using linx_s_alloc\n" : "");
	printf("Test parameters:\n");
	printf("  Hunt path    : %s\n", path);
	printf("  Loop count   : %d\n", cnt);

	for (i = 0; i < cnt; i++)
	{
		int t = test_once(linx, server, use_linx_api, use_pthreads, use_linx_s_alloc);

		if (t > max)
      {
			max = t;
      }

		if (t < min)
      {
			min = t;
      }
		ack += t;
	}

	mean = ack / cnt;

	printf("Attach test completed.\n");
	printf("Result:\n");
	printf("  Average : %.1f us\n", mean);
	printf("  Min     : %ld us\n", min);
	printf("  Max     : %ld us\n", max);
	printf("  Diff    : %ld us\n", max - min);

    /* Write the performance measurings file */
	if (log_perf_monitor) {
    	of = fopen(outfile, "a");
		if (NULL == of) {
			fprintf(stderr, "Failure opening file %s: %s\n", outfile, strerror(errno));
	   	    return 1;
    	}

    	memset(buf, '\0', 128);
    	sprintf(buf, " ### START OF MEASURINGS \n L4L - attach benchmark[us]: %.1f", mean);

    	if (1 < fwrite(buf, strlen(buf), 1, of)) {
    	   fprintf(stderr, "Failure writing data to file %s: %s\n",
    	           outfile, strerror(errno));
    	   exit(1);
    	}

    	if (0 != fclose(of)) {
				fprintf(stderr, "Failure closing file %s: %s\n",
						outfile, strerror(errno));
				exit(1);
		}
	}

	return 0;
}

