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

#include "linx_bmark.h"

/****************************************/

union LINX_SIGNAL
{
   LINX_SIGSELECT sigNo;
};

/****************************************/

int
linx_bmark_latency(LINX *linx, const char *path, int cnt,
                   size_t start_msg_size, size_t end_msg_size,
                   int iterations, LINX_SPID server, int use_linx_api,
                   int use_pthreads, int use_linx_s_alloc)
{
   LINX_SPID test_slave;
   static const LINX_SIGSELECT any_sig[] = { 0 };
   int i;
   int iter = 1;
   long clk = 0;

   struct timeval tv = { 0, 0};
   union LINX_SIGNAL *sig;
   size_t msg_size;
   char buf[868], xbuf[512], ybuf[256];
   FILE *of;

   static unsigned int starttimes[PROC_STAT];
   static unsigned int stoptimes[PROC_STAT];
   int sd = linx_get_descriptor(linx);

   /* Clean buffers */
   memset(buf, '\0', 868);
   memset(xbuf, '\0', 512);
   memset(ybuf, '\0', 256);

   printf("%%%% Running LINX latency bmark %s linx api %%%%\n",
          use_linx_api ? "with" : "without");
   printf("%s", use_linx_api && use_linx_s_alloc ? "Using linx_s_alloc\n" : "");
   printf("Test parameters:\n");
   printf("  Hunt path    : %s\n", path);
   printf("  Loop count   : %d\n", cnt);

   test_slave = create_test_slave(linx, server, use_linx_api,
                                  use_pthreads, use_linx_s_alloc);

   msg_size = start_msg_size;

   if (use_linx_api)
   {
      do
      {
         printf("Running subtest %d of %d\n", iter++, iterations);
         printf("  Message size : %zd bytes\n", msg_size);

         if (use_linx_s_alloc == 1)
         {
            sig = linx_s_alloc(linx, msg_size, ECHO_SIG,0);
         }
         else
         {
            sig = linx_alloc(linx, msg_size, ECHO_SIG);
         }

         /* Start measuring */
         memcpy(starttimes, get_cpu_times(), sizeof(starttimes));
         get_time(&tv);

         for (i = 0; i < cnt; i++)
         {
            linx_send(linx, &sig, test_slave);
            linx_receive(linx, &sig, any_sig);
         }

         /* Stop measuring */
         clk = get_time(&tv);
         memcpy(stoptimes, get_cpu_times(), sizeof(stoptimes));

         linx_free_buf(linx, &sig);

         printf("Test completed.\n\n");
         printf("Result:\n");
         printf("  Total time             : %.1lu us\n", clk);
         printf("  Round-trip latency/msg : %.1lu us\n",
                clk / cnt);

         print_cpu_load(starttimes, stoptimes);

         if (msg_size == start_msg_size)
         {
            sprintf(xbuf, "Sig Size %.1zu ", msg_size);
            sprintf(ybuf, "%.1lu", clk);
         }
         else
         {
            sprintf(xbuf + strlen(xbuf), ", Sig Size %.1zu ", msg_size);
            sprintf(ybuf + strlen(ybuf), ", %.1lu", clk);
         }

         if (end_msg_size != start_msg_size && iterations != 1)
         {
            msg_size += (end_msg_size - start_msg_size) / (iterations - 1);
         }
         else
         {
            break;
         }
      } while (msg_size <= end_msg_size);
   }
   else
   {
      do
      {
         int len;
         struct sockaddr_linx sockaddr;
         socklen_t socklen;

         socklen = sizeof(struct sockaddr_linx);
         sockaddr.family = AF_LINX;
         sockaddr.spid = test_slave;

         printf("Running subtest %d of %d\n", iter++, iterations);
         printf("  Message size : %zd bytes\n", msg_size);

         sig = malloc(msg_size);
         if (sig == NULL)
         {
            ERR("Out of memory");
         }
         sig->sigNo = ECHO_SIG;

         /* Start measuring */
         memcpy(starttimes, get_cpu_times(), sizeof(starttimes));
         get_time(&tv);

         for (i = 0; i < cnt; i++)
         {
            len = sendto(sd, sig, msg_size, 0, (void *)
                         &sockaddr, socklen);

            if (unlikely((size_t) len != msg_size || len <= 0))
            {
               ERR("Failed to send echo signal. "
                   "sendto returned: %d when asked "
                   "for: %zd", len, msg_size);
            }

            len = recvfrom(sd, sig, msg_size, 0, (void *)
                           &sockaddr, &socklen);

            if (unlikely(len <= 0))
            {
               ERR("Failed to receive a echo "
                   "signal(%d, %d)\n", len, errno);
            }
         }

         /* Stop measuring */
         clk = get_time(&tv);
         memcpy(stoptimes, get_cpu_times(), sizeof(starttimes));

         free(sig);

         printf("Test completed.\n\n");

         printf("Result:\n");
         printf("  Total time             : %.1lu us\n", clk);
         if (cnt != 0)
         {
            printf("  Round-trip latency/msg : %.1lu us\n",
                   clk / cnt);
         }
         print_cpu_load(starttimes, stoptimes);

         if (log_perf_monitor) {
            if (msg_size == start_msg_size)
            {
               sprintf(xbuf, "Sig Size %.1zu ", msg_size);
               sprintf(ybuf, "%.1lu", clk);
            }
            else
            {
               sprintf(xbuf + strlen(xbuf), ", Sig Size %.1zu ", msg_size);
               sprintf(ybuf + strlen(ybuf), ", %.1lu", clk);
            }
         }

         if (end_msg_size != start_msg_size && iterations != 1)
         {
            msg_size += (end_msg_size - start_msg_size) / (iterations - 1);
         }
         else
         {
            break;
         }
      } while (msg_size <= end_msg_size);
   }

   /* Write the performance measurings file */
   if (log_perf_monitor) {
      of = fopen(outfile, "a");
      if (NULL == of) {
         fprintf(stderr, "Failure opening file %s: %s\n", outfile, strerror(errno));
         return 1;
      }

      sprintf(buf, " ### START OF MEASURINGS \n L4L - latency benchmark %d iteration(s) [%s]: %s", iterations, xbuf, ybuf);

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

   destroy_test_slave(linx, test_slave);

   return 0;
}

