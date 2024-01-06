/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * canxlrcv.c - CAN XL frame receiver
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <unistd.h>
#include <string.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>

#include <linux/sockios.h>
#include <linux/can.h>
#include <linux/can/raw.h>

#include "printframe.h"

#define ANYDEV "any"
#define DEFAULT_DLEN 10

extern int optind, opterr, optopt;

void print_usage(char *prg)
{
	fprintf(stderr, "%s - CAN XL frame receiver\n\n", prg);
	fprintf(stderr, "Usage: %s [options] <CAN interface>\n", prg);
	fprintf(stderr, "Options:\n");
	fprintf(stderr, "         -V <vcid>:<vcid_mask> (VCID filter)\n");
	fprintf(stderr, "         -l <length> (crop data output, default %d, 0 = disable)\n", DEFAULT_DLEN);
	fprintf(stderr, "         -P (check data pattern)\n");
	fprintf(stderr, "\n");
	fprintf(stderr, "Optional filter sets can be specified on the commandline\n");
	fprintf(stderr, "in the form: <CAN interface>[,filter]*\n");
	fprintf(stderr, "\nFilters:\n");
	fprintf(stderr, "  Comma separated filters can be specified for each given CAN interface:\n");
	fprintf(stderr, "    <can_id>:<can_mask>\n         (matches when <received_can_id> & mask == can_id & mask)\n");
	fprintf(stderr, "    <can_id>~<can_mask>\n         (matches when <received_can_id> & mask != can_id & mask)\n");
	fprintf(stderr, "    #<error_mask>\n         (set error frame filter, see include/linux/can/error.h)\n");
	fprintf(stderr, "    [j|J]\n         (join the given CAN filters - logical AND semantic)\n");
	fprintf(stderr, "\nCAN IDs, masks and data content are given and expected in hexadecimal values.\n");
	fprintf(stderr, "Without any given filter all data frames are received ('0:0' default filter).\n");
	fprintf(stderr, "Use interface name '%s' to receive from all CAN interfaces.\n", ANYDEV);
}

int main(int argc, char **argv)
{
	int opt;
	int s;
	struct can_raw_vcid_options vcid_opts = {};
	struct sockaddr_can addr;
	struct ifreq ifr;
	int max_devname_len = 0; /* to prevent frazzled device name output */
	unsigned int maxdlen = DEFAULT_DLEN;
	int nbytes, ret, i;
	int sockopt = 1;
	int vcid = 0;
	int check_pattern = 0;
	int numfilter;
	int join_filter;
	char *ptr, *nptr;
	can_err_mask_t err_mask;
	struct can_filter *rfilter;
	struct timeval tv;
	union {
		struct can_frame cc;
		struct canfd_frame fd;
		struct canxl_frame xl;
	} can;

	while ((opt = getopt(argc, argv, "V:l:Ph?")) != -1) {
		switch (opt) {

		case 'V':
			if (sscanf(optarg, "%hhx:%hhx",
				   &vcid_opts.rx_vcid,
				   &vcid_opts.rx_vcid_mask) != 2) {
				print_usage(basename(argv[0]));
				return 1;
			}
			vcid = 1;
			break;

		case 'l':
			maxdlen =  strtoul(optarg, NULL, 0);
			if ((maxdlen == 0) || (maxdlen > CANXL_MAX_DLEN))
				maxdlen = CANXL_MAX_DLEN;
			break;

		case 'P':
			check_pattern = 1;
			break;

		case '?':
		case 'h':
		default:
			print_usage(basename(argv[0]));
			return 1;
			break;
		}
	}

	if (optind == argc) {
		print_usage(basename(argv[0]));
		exit(0);
	}

	ptr = argv[optind];
	nptr = strchr(ptr, ',');

	if (nptr)
		nbytes = nptr - ptr; /* interface name is up the first ',' */
	else
		nbytes = strlen(ptr); /* no ',' found => no filter definitions */

	if (nbytes >= IFNAMSIZ) {
		fprintf(stderr, "name of CAN device '%s' is too long!\n", ptr);
		return 1;
	}

	s = socket(PF_CAN, SOCK_RAW, CAN_RAW);
	if (s < 0) {
		perror("socket");
		return 1;
	}

	memset(&ifr.ifr_name, 0, sizeof(ifr.ifr_name));
	strncpy(ifr.ifr_name, ptr, nbytes);

	if (strcmp(ANYDEV, ifr.ifr_name) != 0) {
		if (ioctl(s, SIOCGIFINDEX, &ifr) < 0) {
			perror("SIOCGIFINDEX");
			exit(1);
		}
		addr.can_ifindex = ifr.ifr_ifindex;
	} else
		addr.can_ifindex = 0; /* any can interface */

	addr.can_family = AF_CAN;

	if (nptr) {
		/* found a ',' after the interface name => check for filters */

		/* determine number of filters to alloc the filter space */
		numfilter = 0;
		ptr = nptr;
		while (ptr) {
			numfilter++;
			ptr++; /* hop behind the ',' */
			ptr = strchr(ptr, ','); /* exit condition */
		}

		rfilter = malloc(sizeof(struct can_filter) * numfilter);
		if (!rfilter) {
			fprintf(stderr, "Failed to create filter space!\n");
			return 1;
		}

		numfilter = 0;
		err_mask = 0;
		join_filter = 0;

		while (nptr) {

			ptr = nptr + 1; /* hop behind the ',' */
			nptr = strchr(ptr, ','); /* update exit condition */

			if (sscanf(ptr, "%x:%x",
				   &rfilter[numfilter].can_id,
				   &rfilter[numfilter].can_mask) == 2) {
				rfilter[numfilter].can_mask &= ~CAN_ERR_FLAG;
				numfilter++;
			} else if (sscanf(ptr, "%x~%x",
					  &rfilter[numfilter].can_id,
					  &rfilter[numfilter].can_mask) == 2) {
				rfilter[numfilter].can_id |= CAN_INV_FILTER;
				rfilter[numfilter].can_mask &= ~CAN_ERR_FLAG;
				numfilter++;
			} else if (*ptr == 'j' || *ptr == 'J') {
				join_filter = 1;
			} else if (sscanf(ptr, "#%x", &err_mask) != 1) {
				fprintf(stderr, "Error in filter option parsing: '%s'\n", ptr);
				return 1;
			}
		}

		if (err_mask)
			setsockopt(s, SOL_CAN_RAW, CAN_RAW_ERR_FILTER,
				   &err_mask, sizeof(err_mask));

		if (join_filter && setsockopt(s, SOL_CAN_RAW, CAN_RAW_JOIN_FILTERS,
					      &join_filter, sizeof(join_filter)) < 0) {
			perror("setsockopt CAN_RAW_JOIN_FILTERS not supported by your Linux Kernel");
			return 1;
		}

		if (numfilter)
			setsockopt(s, SOL_CAN_RAW, CAN_RAW_FILTER,
				   rfilter, numfilter * sizeof(struct can_filter));

		free(rfilter);

	} /* if (nptr) */

	ret = setsockopt(s, SOL_CAN_RAW, CAN_RAW_XL_FRAMES,
			 &sockopt, sizeof(sockopt));
	if (ret < 0) {
		perror("sockopt CAN_RAW_XL_FRAMES");
		return 1;
	}

	if (vcid) {
		vcid_opts.flags = CAN_RAW_XL_VCID_RX_FILTER;
		ret = setsockopt(s, SOL_CAN_RAW, CAN_RAW_XL_VCID_OPTS,
				 &vcid_opts, sizeof(vcid_opts));
		if (ret < 0) {
			perror("sockopt CAN_RAW_XL_VCID_OPTS");
			exit(1);
		}
	}

	if (bind(s, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		perror("bind");
		return 1;
	}

	while (1) {
		socklen_t len = sizeof(addr);

		nbytes = recvfrom(s, &can.xl, sizeof(struct canxl_frame),
				  0, (struct sockaddr*)&addr, &len);
		if (nbytes < 0) {
			perror("read");
			return 1;
		}
		
		if (ioctl(s, SIOCGSTAMP, &tv) < 0) {
			perror("SIOCGSTAMP");
			return 1;
		} else {
			printf("(%ld.%06ld) ", tv.tv_sec, tv.tv_usec);
		}

		ifr.ifr_ifindex = addr.can_ifindex;
		if (ioctl(s, SIOCGIFNAME, &ifr) < 0) {
			perror("SIOCGIFNAME");
			return 1;
		} else {
			if (max_devname_len < (int)strlen(ifr.ifr_name))
				max_devname_len = strlen(ifr.ifr_name);
			printf("%*s ", max_devname_len, ifr.ifr_name);
		}

		if (nbytes < CANXL_HDR_SIZE + CANXL_MIN_DLEN) {
			fprintf(stderr, "read: no CAN frame\n");
			return 1;
		}

		if (can.xl.flags & CANXL_XLF) {
			if (nbytes != CANXL_HDR_SIZE + can.xl.len) {
				printf("nbytes = %d\n", nbytes);
				fprintf(stderr, "read: no CAN XL frame\n");
				return 1;
			}

			if (check_pattern) {
				for (i = 0; i < can.xl.len; i++) {
					if (can.xl.data[i] != ((can.xl.len + i) & 0xFFU)) {
						fprintf(stderr, "check pattern failed %02X %04X\n",
							can.xl.data[i], can.xl.len + i);
						return 1;
					}
				}
			}
			printxlframe(&can.xl, maxdlen);
			continue;
		}

		if (nbytes == CANFD_MTU) {
			printfdframe(&can.fd);
			continue;
		}

		if (nbytes == CAN_MTU) {
			printccframe(&can.cc);
			continue;
		}

		fprintf(stderr, "read: incomplete CAN(FD) frame\n");
		return 1;
	}

	close(s);

	return 0;
}
