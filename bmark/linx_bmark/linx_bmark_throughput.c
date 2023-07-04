/*
 * Copyright (C) 2006-2017 by Enea Software AB.
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
#include <sys/wait.h>
#include <pthread.h>

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

struct client_args
{
   size_t msg_size;
   int cnt;
   LINX_SPID server;
   int use_linx_api;
   int use_pthreads;
   int use_linx_s_alloc;
};

static void*
test_client_dummy(void *input)
{
   union LINX_SIGNAL *sig;
   LINX *linx = linx_open("test_client", 0, NULL);
   
   size_t msg_size = ((struct client_args *)input)->msg_size;
   LINX_SPID server = ((struct client_args *)input)->server;
   int use_linx_api = ((struct client_args *)input)->use_linx_api;
   int use_pthreads = ((struct client_args *)input)->use_pthreads;
   int use_linx_s_alloc = ((struct client_args *)input)->use_linx_s_alloc;

   LINX_SPID slave = create_test_slave(linx, server, use_linx_api,
                                       use_pthreads, use_linx_s_alloc);

   /* this is to even out the measurement */
   if (use_linx_api == 1)
   {
      if (use_linx_s_alloc == 1)
      {
         sig = linx_s_alloc(linx, msg_size, ECHO_SIG, 0);
      }
      else
      {
         sig = linx_alloc(linx, msg_size, ECHO_SIG);
      }
      linx_free_buf(linx, &sig);
   }
   else
   {
      struct sockaddr_linx sockaddr;
      socklen_t socklen;
      char *buf = malloc(msg_size);

      if (buf == NULL)
      {
         ERR("Could not allocate memory");
         exit(1);
      }

      sig = (void *)buf;
      socklen = sizeof(struct sockaddr_linx);
      sockaddr.family = AF_LINX;
      sockaddr.spid = slave;
      (void)socklen;
      (void)sockaddr;

      sig->sigNo = ECHO_SIG;
      free(buf);
   }
   destroy_test_slave(linx, slave);
   linx_close(linx);

   return NULL;
}

static void*
test_client(void *input)
{
   int i;
   union LINX_SIGNAL *sig;
   static const LINX_SIGSELECT any_sig[] = { 0 };
   char *buf;   /* buffer used when not using linx api. */

   LINX *linx = linx_open("test_client", 0, NULL);

   size_t msg_size = ((struct client_args *)input)->msg_size;
   int cnt = ((struct client_args *)input)->cnt;
   LINX_SPID server = ((struct client_args *)input)->server;
   int use_linx_api = ((struct client_args *)input)->use_linx_api;
   int use_pthreads = ((struct client_args *)input)->use_pthreads;
   int use_linx_s_alloc = ((struct client_args *)input)->use_linx_s_alloc;

   LINX_SPID slave = create_test_slave(linx, server, use_linx_api,
                             use_pthreads, use_linx_s_alloc);

   if (use_linx_api)
   {
      if (use_linx_s_alloc == 1)
      {
         sig = linx_s_alloc(linx, msg_size, ECHO_SIG, 0);
      }
      else
      {
         sig = linx_alloc(linx, msg_size, ECHO_SIG);
      }

      for (i = 0; i < cnt; i++)
      {
         linx_send(linx, &sig, slave);
         linx_receive(linx, &sig, any_sig);
      }
      linx_free_buf(linx, &sig);
   }
   else
   {
      int len;
      struct sockaddr_linx sockaddr;
      socklen_t socklen;
      int sd = linx_get_descriptor(linx);

      buf = malloc(msg_size);
      if (buf == NULL)
      {
         ERR("Could not allocate memory");
         exit(1);
      }

      sig = (void *)buf;
      socklen = sizeof(struct sockaddr_linx);
      sockaddr.family = AF_LINX;
      sockaddr.spid = slave;

      sig->sigNo = ECHO_SIG;

      for (i = 0; likely(i < cnt); i++)
      {
         len = sendto(sd, sig, msg_size, 0,
                      (void *)&sockaddr, socklen);

         if (unlikely((size_t) len != msg_size || len <= 0))
         {
            ERR("Failed to send echo signal. "
                "sendto returned: %d when asked "
                "for: %zd", len, msg_size);
         }

         len = recvfrom(sd, sig, msg_size, 0,
                        (void *)&sockaddr, &socklen);

         if (unlikely(len <= 0))
         {
            ERR("Failed to receive a echo signal"
                "(%d, %d)\n", len, errno);
         }
      }
      free(buf);
   }

   destroy_test_slave(linx, slave);
   linx_close(linx);

   return NULL;
}

int
linx_bmark_throughput(const char *path, int cnt,
                      size_t msg_size, LINX_SPID server,
                      int use_linx_api, int tp_instances,
                      int use_pthreads, int use_linx_s_alloc)
{
   int i;
   struct timeval tv = { 0, 0 };
   long clk = 0;
   static unsigned int starttimes[PROC_STAT];
   static unsigned int stoptimes[PROC_STAT];
   pid_t pid;
   pthread_t child[256];
   char buf[128];
   FILE *of;

   printf("\n%%%% Running LINX throughput bmark %s linx api %%%%\n",
          use_linx_api ? "with" : "without");
   printf("%s", use_linx_api && use_linx_s_alloc ? "Using linx_s_alloc\n" : "");
   printf("Test parameters:\n");
   printf("  Hunt path    : %s\n", path);
   printf("  Loop count   : %d\n", cnt);
   printf("  Message size : %zd bytes\n", msg_size);
   printf("  Instances    : %u\n", tp_instances);

   memset(child, 0, sizeof(child));

   fflush(stdout);

   memcpy(starttimes, get_cpu_times(), sizeof(starttimes));

   get_time(&tv);

   for (i = 0; i < tp_instances; i++)
   {
      if (use_pthreads)
      {
         struct client_args input;

         input.msg_size = msg_size;
         input.cnt = cnt;
         input.server = server;
         input.use_linx_api = use_linx_api;
         input.use_pthreads = 1;
         input.use_linx_s_alloc = use_linx_s_alloc;

         if (pthread_create(&child[i], NULL, test_client, (void *)&input))
         {
            fprintf(stderr, "pthread_create(): %d\n", errno);
            exit(errno);
         }
      }
      else
      {
         pid = fork();

         if (pid < 0)
         {
            ERR("server failed to fork. pid %d", pid);
         }

         if (!pid)
         {
            struct client_args input;

            input.msg_size = msg_size;
            input.cnt = cnt;
            input.server = server;
            input.use_linx_api = use_linx_api;
            input.use_pthreads = 0;
            input.use_linx_s_alloc = use_linx_s_alloc;

            (void)test_client(&input);

            _exit(0);
         }
      }
   }

   for (i = 0; i < tp_instances; i++)
   {
      if (use_pthreads)
      {
         pthread_join(child[i], NULL);
      }
      else
      {
         wait(NULL);
      }
   }

   clk = get_time(&tv);
   memcpy(stoptimes, get_cpu_times(), sizeof(stoptimes));

   memset(child, 0, sizeof(child));

   /* Measure the time it takes to create the test processes without
    * doing any test and remove it from the clk time (this oh shall
    * not be part of the measurement.)
    */
   get_time(&tv);

   for (i = 0; i < tp_instances; i++)
   {
      if (use_pthreads)
      {
         struct client_args input;

         input.msg_size = msg_size;
         input.cnt = cnt;
         input.server = server;
         input.use_linx_api = use_linx_api;
         input.use_pthreads = 1;
         input.use_linx_s_alloc = use_linx_s_alloc;

         if (pthread_create(&child[i], NULL, test_client_dummy, (void *)&input))
         {
            fprintf(stderr, "pthread_create(): %d\n", errno);
            exit(errno);
         }
      }
      else
      {
         pid = fork();

         if (pid < 0)
         {
            ERR("Server failed to fork, pid: %d\n", pid);
         }

         if (!pid)
         {
            struct client_args input;

            input.msg_size = msg_size;
            input.cnt = cnt;
            input.server = server;
            input.use_linx_api = use_linx_api;
            input.use_pthreads = 0;
            input.use_linx_s_alloc = use_linx_s_alloc;

            (void)test_client_dummy(&input);
            _exit(0);
         }
      }
   }

   for (i = 0; i < tp_instances; i++)
   {
      if (use_pthreads)
      {
         pthread_join(child[i], NULL);
      }
      else
      {
         wait(NULL);
      }
   }

   clk -= get_time(&tv);

   printf("LINX troughput bmark completed.\n");
   printf("Results:\n");
   {
      long long bits = (long long)msg_size;
      bits *= tp_instances;
      bits *= cnt;
      bits *= 2;
      bits *= 8;

      printf(": Benchmark time %ld us\n", clk);
      printf("  Sent bits   : %lld Bits/direction\n", bits / 2);
      printf("  Performance : %lld Mbps/direction\n",
             bits / 2 / (long long)clk);
      print_cpu_load(starttimes, stoptimes);

      /* Write the performance measurings file */
      if (log_perf_monitor) {
         of = fopen(outfile, "a");
         if (NULL == of) {
            fprintf(stderr, "Failure opening file %s: %s\n", outfile, strerror(errno));
            return 1;
         }

         memset(buf, '\0', 128);
         sprintf(buf, " ### START OF MEASURINGS \n L4L - throughput benchmark [Bits/direction]: %lld", bits / 2);

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
   }


   return 0;
}

