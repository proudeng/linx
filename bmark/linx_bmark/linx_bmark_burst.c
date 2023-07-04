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
#include <sys/socket.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>

#include <linx.h>
#include <linx_types.h>
#include <linx_ioctl.h>
#include <linx_socket.h>

#include <arpa/inet.h>

#include "linx_bmark.h"

/****************************************/

/*
 * burstSig and allocReq are defined in linx_bmark.h
 */
union LINX_SIGNAL
{
   LINX_SIGSELECT sigNo;
   struct burstSig burstSig;
   struct allocReq allocReq;
};

/****************************************/

int
linx_bmark_burst(LINX *linx, const char *path, int cnt,
                 size_t start_msg_size, size_t end_msg_size,
                 int iterations,
                 uint32_t burst_cnt, LINX_SPID server,
                 int use_linx_api, int use_pthreads,
                 int use_linx_s_alloc)
{
   LINX_SPID test_slave;
   static const LINX_SIGSELECT any_sig[] = { 0 };
   static const LINX_SIGSELECT alloc_fini_sig[] = { 1, ALLOC_FINI };
   int iter = 1;
   size_t msg_size;
   int sd = linx_get_descriptor(linx);
   int i;
   union LINX_SIGNAL *list = NULL;
   char buf[868], xbuf[512], ybuf[256];
   FILE *of;

   /* Clean buffers */
   memset(xbuf, '\0', 512);
   memset(ybuf, '\0', 256);

   printf("\n%%%% Running LINX burst bmark %s linx api %%%%\n",
          use_linx_api ? "with" : "without");
   printf("%s", use_linx_api && use_linx_s_alloc ? "Using linx_s_alloc\n" : "");
   printf("Test parameters:\n");
   printf("  Burst count  : %u\n", (unsigned)burst_cnt);
   printf("  Hunt path    : %s\n", path);
   printf("  Loop count   : %d\n", cnt);

   test_slave = create_test_slave(linx, server, use_linx_api,
                                  use_pthreads, use_linx_s_alloc);
   msg_size = start_msg_size;

   do
   {
      float mean;
      long ack = 0;
      long max = 0;
      long min = LONG_MAX;

      static unsigned int starttimes[PROC_STAT];
      static unsigned int stoptimes[PROC_STAT];

      printf("Running subtest %d of %d", iter++, iterations);
      printf(" with message size : %zd bytes\n", msg_size);

      if (use_linx_api)
      {
         for (i = 0; i < cnt; i++)
         {
            uint32_t j;
            union LINX_SIGNAL *sig;
            struct timeval tv = { 0, 0 };
            long clk;

            sig = linx_alloc(linx, sizeof(struct allocReq), ALLOC_REQ);
            sig->allocReq.n = htonl(burst_cnt);
            sig->allocReq.reply_size = (uint32_t)htonl(msg_size);
            sig->allocReq.reply_sigNo = (LINX_SIGSELECT)htonl(BURST_SIGNO);

				/* Send the ALLOC_REQ to slave to allocate the signals. */
				linx_send(linx, &sig, test_slave);
				/*
				 * Wait for confimation from the slave that the signals
				 * have been allocated.
				 */
				linx_receive(linx, &sig, alloc_fini_sig);
				linx_free_buf(linx, &sig);

				/* Send the BURST_REQ to slave to start sending the signals. */
            sig = linx_alloc(linx, sizeof(LINX_SIGSELECT), BURST_REQ);
				linx_send(linx, &sig, test_slave);

            /* Start measuring */
            memcpy(starttimes, get_cpu_times(), sizeof(starttimes));
            get_time(&tv);

            for (j = 0; j < burst_cnt; j++)
            {
               linx_receive(linx, &sig, any_sig);
               sig->burstSig.next = list;
               list = sig;
            }

            /* Stop measuring */
            clk = get_time(&tv);
            memcpy(stoptimes, get_cpu_times(), sizeof(stoptimes));

            PRINT(DBG, "Response time: %ld us\n", clk);

            while (list)
            {
               sig = list;
               list = list->burstSig.next;

               if (sig->sigNo != BURST_SIGNO)
               {
                  ERR("Unknown signal %u", sig->sigNo);
               }
               linx_free_buf(linx, &sig);
            }

            if (clk > max)
            {
               max = clk;
            }
            if (clk < min)
            {
               min = clk;
            }
            ack += clk;

         }
      }
      else
      {
         union LINX_SIGNAL *sig;
         int len;
         struct sockaddr_linx sockaddr;
         socklen_t socklen;

         sig = malloc(sizeof(struct allocReq) > end_msg_size ?
                      sizeof(struct allocReq) : end_msg_size);
         if (sig == NULL)
         {
            ERR("Out of memory");
         }

         socklen = sizeof(struct sockaddr_linx);
         sockaddr.family = AF_LINX;
         sockaddr.spid = test_slave;

         for (i = 0; i < cnt; i++)
         {
            uint32_t j;
            struct timeval tv = { 0, 0 };
            long clk;

            sockaddr.spid = test_slave;

            sig->sigNo = ALLOC_REQ;
            sig->allocReq.n = htonl(burst_cnt);
            sig->allocReq.reply_size = (uint32_t)htonl(msg_size);
            sig->allocReq.reply_sigNo = (LINX_SIGSELECT)htonl(BURST_SIGNO);

            len = sendto(sd, sig, sizeof(struct allocReq),
                         0, (void *)&sockaddr, socklen);

            if (unlikely((size_t)len != sizeof(struct allocReq) || len <= 0))
            {
               ERR("Failed to send echo signal. "
                   "sendto returned: %d when asked "
                   "for: %zd", len, msg_size);
            }

            len = recvfrom(sd, sig, sizeof(struct allocReq), 0,
                           (void *)&sockaddr, &socklen);

            if (unlikely(len <= 0))
            {
               ERR("Failed to receive an "
                   "echo signal(%d, %d)\n",
                   len, errno);
            }

            if (unlikely(sig->sigNo != ALLOC_FINI))
            {
               ERR("Unknown signal 0x%x", sig->sigNo);
            }

            sig->sigNo = BURST_REQ;
            len = sendto(sd, sig, sizeof(struct allocReq),
                         0, (void *)&sockaddr, socklen);

            if (unlikely(len <= 0))
            {
               ERR("Failed to start BURST_REQ %d\n", errno);
            }

            /* Start measuring */
            memcpy(starttimes, get_cpu_times(), sizeof(starttimes));
            get_time(&tv);

            for (j = 0; j < burst_cnt; j++)
            {
               len = recvfrom(sd, sig, msg_size, 0,
                              (void *)&sockaddr, &socklen);

               if (unlikely(len <= 0))
               {
                  ERR("Failed to receive an echo signal(%d, %d)\n",
                      len, errno);
               }

               if (unlikely(sig->sigNo != BURST_SIGNO))
               {
						ERR("Unknown signal %u", sig->sigNo);
					}
            }

            /* Stop measuring */
            clk = get_time(&tv);
            memcpy(stoptimes, get_cpu_times(), sizeof(stoptimes));

            PRINT(DBG, "Response time: %ld us\n", clk);

            if (clk > max)
            {
               max = clk;
            }

            if (clk < min)
            {
               min = clk;
            }
            ack += clk;
         } /* for */

         free(sig);
      } /* else */

      mean = ack / cnt;

      printf("  Result:\n");
      printf("  Average : %.1f us\n", mean);
      printf("  Min     : %ld us\n", min);
      printf("  Max     : %ld us\n", max);
      printf("  Diff    : %ld us\n", max - min);

      print_cpu_load(starttimes, stoptimes);

      if (log_perf_monitor) {
         if (msg_size == start_msg_size) {
            sprintf(xbuf, "Sig Size %zu", msg_size);
            sprintf(ybuf, "%.1f", mean);
         } else {
            sprintf(xbuf + strlen(xbuf), ", Sig Size %zu", msg_size);
            sprintf(ybuf + strlen(ybuf), ", %.1f", mean);
         }
      }

      if (end_msg_size != start_msg_size && iterations != 1) {
         msg_size += (end_msg_size - start_msg_size) / (iterations - 1);
      } else {
         break;
      }
   } while (msg_size <= end_msg_size);

   destroy_test_slave(linx, test_slave);

   /* Write the performance measurings file */
   if (log_perf_monitor) {
      of = fopen(outfile, "a");
      if (NULL == of) {
         fprintf(stderr, "Failure opening file %s: %s\n", outfile, strerror(errno));
         return 1;
      }

      memset(buf, '\0', 868);
      sprintf(buf, " ### START OF MEASURINGS \n L4L - burst benchmark %d iteration(s) [%s]: %s", iterations, xbuf, ybuf);

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

   printf("Burst test completed\n");

   return 0;
}

