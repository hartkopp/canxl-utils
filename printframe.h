#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <linux/can.h>

typedef union {
	struct can_frame cc;
	struct canfd_frame fd;
	struct canxl_frame xl;
} cu_t;

static inline void printxlframe(struct canxl_frame *cfx, unsigned int maxdlen)
{
	int i;
	canid_t vcid = (cfx->prio & CANXL_VCID_MASK) >> CANXL_VCID_OFFSET;
	canid_t prio = (cfx->prio & CANXL_PRIO_MASK);

	/* print prio and CAN XL header content */
	printf("%02X%03X", vcid, prio);
	printf("#%02X:%02X:%08X#", cfx->flags, cfx->sdt, cfx->af);

	/* print up to maxdlen data bytes */
	for (i = 0; i < cfx->len && i < maxdlen; i++) {
		if (!(i%4) && (i))
			printf(".");
		printf("%02X", cfx->data[i]);
	}

	/* print CAN XL data length when cropped */
	if (cfx->len > maxdlen)
		printf("(%d)", cfx->len);

	printf("\n");

	fflush(stdout);
}

static inline void printfdframe(struct canfd_frame *cfd)
{
	int i;

	if (cfd->can_id & CAN_EFF_FLAG)
		printf("%08X#", cfd->can_id & CAN_EFF_MASK);
	else
		printf("%03X#", cfd->can_id & CAN_SFF_MASK);

	printf("#%X", cfd->flags & 0xF);

	for (i = 0; i < cfd->len; i++)
		printf("%02X", cfd->data[i]);

	printf("\n");
	fflush(stdout);
}

static inline void printccframe(struct can_frame *cf)
{
	int i;

	if (cf->can_id & CAN_EFF_FLAG)
		printf("%08X#", cf->can_id & CAN_EFF_MASK);
	else
		printf("%03X#", cf->can_id & CAN_SFF_MASK);

	if (cf->can_id & CAN_RTR_FLAG) {
		printf("R");
		if (cf->len > 0)
			printf("%d", cf->len);
	} else {
		for (i = 0; i < cf->len; i++)
			printf("%02X", cf->data[i]);
	}
	if (cf->len == CAN_MAX_DLEN &&
	    cf->len8_dlc > CAN_MAX_DLEN &&
	    cf->len8_dlc <= CAN_MAX_RAW_DLC)
		printf("_%X", cf->len8_dlc);

	printf("\n");
	fflush(stdout);
}
