cmd_/home/proudeng/Code/linx-2.6.9/net/linx/shmcm/linx_shm_cm.mod := printf '%s\n'   shmcm.o shmcm_rx.o shmcm_tx.o shmcm_kutils.o | awk '!x[$$0]++ { print("/home/proudeng/Code/linx-2.6.9/net/linx/shmcm/"$$0) }' > /home/proudeng/Code/linx-2.6.9/net/linx/shmcm/linx_shm_cm.mod
