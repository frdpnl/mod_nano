/*
 * MOD_NANO test client.
 */

#include <stdio.h>
#include <error.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

#include <nanomsg/nn.h>
#include <nanomsg/ipc.h>
#include <nanomsg/reqrep.h>

void exit4err(const char *label, int rc, int fail)
{
	if (rc == fail) {
		perror(label);
		exit(errno);
	}
}

int main(int argc, char *argv[])
{
	if (argc != 2) {
		fprintf(stderr, "usage: %s <endpoint>", argv[0]);
		exit(EXIT_FAILURE);
	}
	int pid = getpid();
	int soc = nn_socket(AF_SP, NN_REP);
	exit4err("nn_socket", soc, -1);
	int end = nn_bind(soc, argv[1]);
	exit4err("nn_bind", end, -1);
	printf("bound to %s\n", argv[1]);
	size_t nbytes = -1;
	size_t replen = 1024;
	void *request;
	char *reply = (char *)calloc(replen, sizeof(char));
	for (int nm = 0;; ++nm) {
		nbytes = nn_recv(soc, &request, NN_MSG, 0);
		if (nbytes == -1) {
			error(0, errno, "%d nn_recv [%s] %zdB", pid, (char *)request, nbytes);
			sleep(1);
			continue;
		}
		char *req = (char *)calloc(nbytes+1, sizeof(char));
		memcpy(req, request, nbytes*sizeof(char));
		req[nbytes] = 0;
		nn_freemsg(request);
		printf("%s pid=%6d nn_recv:\n<%s>[len=%ld][recv=%ld]B\n", 
			__FILE__, pid, req, strlen(req), nbytes);
		nbytes = snprintf(reply, replen -1, 
			"HTTP/1.1 200 Fine\r\nContent-type: text/html\r\n\r\n<html><body><h2>hello %ldB</h2></body></html>", 
			nbytes);
		if (nbytes <= 0 || nbytes >= replen -1) {
			exit4err("snprintf", 0, 0);
		}
		printf ("replying with: <%s>[%u]B.\n", reply, (int)strlen(reply));
		nbytes = nn_send(soc, reply, strlen(reply), 0);
		if (nbytes != strlen(reply)) {
			error(0, errno, "%d nn_send [%s] %zdB", pid, reply, nbytes);
			sleep(1);
			continue;
		}
		printf ("%s pid=%6d nn_sent:\n<%s>[%zd]B\n", __FILE__, pid, reply, nbytes);
		free(req);
	}
	free(reply);
	exit4err("nn_shutdown", nn_shutdown(soc, end), -1);
	exit4err("nn_close", nn_close(soc), -1);
	exit(EXIT_SUCCESS);
}
