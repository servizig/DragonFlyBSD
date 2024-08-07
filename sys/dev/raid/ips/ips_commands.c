/*-
 * Written by: David Jeffery
 * Copyright (c) 2002 Adaptec Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * $FreeBSD: src/sys/dev/ips/ips_commands.c,v 1.10 2004/05/30 04:01:29 scottl Exp $
 */

#include <sys/devicestat.h>
#include <sys/sysctl.h>
#include <dev/raid/ips/ips.h>
#include <dev/raid/ips/ips_disk.h>

static int ips_debug_ignore_flush_cmd;
TUNABLE_INT("debug.ips.ignore_flush_cmd", &ips_debug_ignore_flush_cmd);
SYSCTL_NODE(_debug, OID_AUTO, ips, CTLFLAG_RD, 0, "");
SYSCTL_INT(_debug_ips, OID_AUTO, ignore_flush_cmd, CTLFLAG_RW,
	   &ips_debug_ignore_flush_cmd, 0,
	   "Do not issue IPS_CACHE_FLUSH_CMD on BUF_CMD_FLUSH");

int
ips_timed_wait(ips_command_t *command, const char *id, int timo)
{
	int error = 0;

	while (command->completed == 0) {
		crit_enter();
		if (command->completed == 0)
			error = tsleep(&command->completed, 0, id, timo);
		crit_exit();
		if (error == EWOULDBLOCK) {
			error = ETIMEDOUT;
			break;
		}
	}
	return(error);
}

/*
 * This is an interrupt callback.  It is called from
 * interrupt context when the adapter has completed the
 * command, and wakes up anyone waiting on the command.
 */
static void
ips_wakeup_callback(ips_command_t *command)
{
	bus_dmamap_sync(command->sc->command_dmatag, command->command_dmamap,
			BUS_DMASYNC_POSTWRITE);
	command->completed = 1;
	wakeup(&command->completed);
}

/*
 * Below are a series of functions for sending an IO request
 * to the adapter.  The flow order is: start, send, callback, finish.
 * The caller must have already assembled an iorequest struct to hold
 * the details of the IO request.
 */
static void
ips_io_request_finish(ips_command_t *command)
{
	struct bio *bio = command->arg;

	if (ips_read_request(bio)) {
		bus_dmamap_sync(command->data_dmatag, command->data_dmamap,
				BUS_DMASYNC_POSTREAD);
	} else {
		bus_dmamap_sync(command->data_dmatag, command->data_dmamap,
				BUS_DMASYNC_POSTWRITE);
	}
	bus_dmamap_unload(command->data_dmatag, command->data_dmamap);
	if (COMMAND_ERROR(&command->status)) {
		bio->bio_buf->b_flags |=B_ERROR;
		bio->bio_buf->b_error = EIO;
	}
	ips_insert_free_cmd(command->sc, command);
	ipsd_finish(bio);
}

static void
ips_io_request_callback(void *cmdptr, bus_dma_segment_t *segments, int segnum,
			int error)
{
	ips_softc_t *sc;
	ips_command_t *command = cmdptr;
	ips_sg_element_t *sg_list;
	ips_io_cmd *command_struct;
	struct bio *bio = command->arg;
	struct buf *bp = bio->bio_buf;
	ipsdisk_softc_t *dsc;
	int i, length = 0;
	u_int8_t cmdtype;

	sc = command->sc;
	if (error) {
		kprintf("ips: error = %d in ips_sg_request_callback\n", error);
		bus_dmamap_unload(command->data_dmatag, command->data_dmamap);
		bp->b_flags |= B_ERROR;
		bp->b_error = ENOMEM;
		ips_insert_free_cmd(sc, command);
		ipsd_finish(bio);
		return;
	}
	dsc = bio->bio_driver_info;
	command_struct = (ips_io_cmd *)command->command_buffer;
	command_struct->id = command->id;
	command_struct->drivenum = dsc->sc->drives[dsc->disk_number].drivenum;

	if (segnum != 1) {
		if (ips_read_request(bio))
			cmdtype = IPS_SG_READ_CMD;
		else
			cmdtype = IPS_SG_WRITE_CMD;
		command_struct->segnum = segnum;
		sg_list = (ips_sg_element_t *)((u_int8_t *)
			   command->command_buffer + IPS_COMMAND_LEN);
		for (i = 0; i < segnum; i++) {
			sg_list[i].addr = segments[i].ds_addr;
			sg_list[i].len = segments[i].ds_len;
			length += segments[i].ds_len;
		}
		command_struct->buffaddr =
		    (u_int32_t)command->command_phys_addr + IPS_COMMAND_LEN;
	} else {
		if (ips_read_request(bio))
			cmdtype = IPS_READ_CMD;
		else
			cmdtype = IPS_WRITE_CMD;
		command_struct->buffaddr = segments[0].ds_addr;
		length = segments[0].ds_len;
	}
	command_struct->command = cmdtype;
	command_struct->lba = bio->bio_offset / IPS_BLKSIZE;
	length = (length + IPS_BLKSIZE - 1)/IPS_BLKSIZE;
	command_struct->length = length;
	bus_dmamap_sync(sc->command_dmatag, command->command_dmamap,
			BUS_DMASYNC_PREWRITE);
	if (ips_read_request(bio)) {
		bus_dmamap_sync(command->data_dmatag, command->data_dmamap,
				BUS_DMASYNC_PREREAD);
	} else {
		bus_dmamap_sync(command->data_dmatag, command->data_dmamap,
				BUS_DMASYNC_PREWRITE);
	}
	PRINTF(10, "ips test: command id: %d segments: %d "
		"pblkno: %lld length: %d, ds_len: %d\n", command->id, segnum,
		bio->bio_offset / IPS_BLKSIZE,
		length, segments[0].ds_len);

	sc->ips_issue_cmd(command);
	return;
}

static void
ips_flush_request_finish(ips_command_t *command)
{
	ips_generic_cmd *gencmd = command->command_buffer;
	struct bio *bio = command->arg;

	if (COMMAND_ERROR(&command->status)) {
		device_printf(command->sc->dev,
			      "cmd=0x%x,st=0x%x,est=0x%x\n",
			      gencmd->command,
			      command->status.fields.basic_status,
			      command->status.fields.extended_status);

		bio->bio_buf->b_flags |= B_ERROR;
		bio->bio_buf->b_error = EIO;
	}
	ips_insert_free_cmd(command->sc, command);
	ipsd_finish(bio);
}

static int
ips_send_flush_request(ips_command_t *command, struct bio *bio)
{
	command->arg = bio;
	ips_generic_cmd *flush_cmd;
	ips_softc_t *sc = command->sc;

	if (!ips_debug_ignore_flush_cmd) {
		ips_insert_free_cmd(sc, command);
		ipsd_finish(bio);
		return 0;
	}

	command->callback = ips_flush_request_finish;
	flush_cmd = command->command_buffer;
	flush_cmd->command	= IPS_CACHE_FLUSH_CMD;
	flush_cmd->id		= command->id;
	flush_cmd->drivenum	= 0;
	flush_cmd->buffaddr	= 0;
	flush_cmd->lba		= 0;
	bus_dmamap_sync(sc->command_dmatag, command->command_dmamap,
			BUS_DMASYNC_PREWRITE);

	sc->ips_issue_cmd(command);
	return 0;
}


static int
ips_send_io_request(ips_command_t *command, struct bio *bio)
{
	struct buf *bp = bio->bio_buf;

	command->callback = ips_io_request_finish;
	command->arg = bio;
	PRINTF(10, "ips test: : bcount %ld\n", bp->b_bcount);
	bus_dmamap_load(command->data_dmatag, command->data_dmamap,
			bp->b_data, bp->b_bcount,
			ips_io_request_callback, command, 0);
	return 0;
}

void
ips_start_io_request(ips_softc_t *sc)
{
	ips_command_t *command;
	struct bio *bio;

	bio = bioq_first(&sc->bio_queue);
	if (bio == NULL)
		return;
	if (ips_get_free_cmd(sc, &command, 0) != 0)
		return;
	bioq_remove(&sc->bio_queue, bio);
	if (bio->bio_buf->b_cmd == BUF_CMD_FLUSH)
		ips_send_flush_request(command, bio);
	else
		ips_send_io_request(command, bio);
}

/*
 * Below are a series of functions for sending an adapter info request
 * to the adapter.  The flow order is: get, send, callback. It uses
 * the generic finish callback at the top of this file.
 * This can be used to get configuration/status info from the card
 */
static void
ips_adapter_info_callback(void *cmdptr, bus_dma_segment_t *segments,int segnum,
			  int error)
{
	ips_softc_t *sc;
	ips_command_t *command = cmdptr;
	ips_adapter_info_cmd *command_struct;
	sc = command->sc;
	if (error) {
		command->status.value = IPS_ERROR_STATUS; /* a lovely error value */
		ips_insert_free_cmd(sc, command);
		kprintf("ips: error = %d in ips_get_adapter_info\n", error);
		return;
	}
	command_struct = (ips_adapter_info_cmd *)command->command_buffer;
	command_struct->command = IPS_ADAPTER_INFO_CMD;
	command_struct->id = command->id;
	command_struct->buffaddr = segments[0].ds_addr;

	bus_dmamap_sync(sc->command_dmatag, command->command_dmamap,
			BUS_DMASYNC_PREWRITE);
	bus_dmamap_sync(command->data_dmatag, command->data_dmamap,
			BUS_DMASYNC_PREREAD);
	sc->ips_issue_cmd(command);
}

static int
ips_send_adapter_info_cmd(ips_command_t *command)
{
	ips_softc_t *sc = command->sc;
	int error = 0;

	if (bus_dma_tag_create(	/* parent    */	sc->adapter_dmatag,
				/* alignemnt */	1,
				/* boundary  */	0,
				/* lowaddr   */	BUS_SPACE_MAXADDR_32BIT,
				/* highaddr  */	BUS_SPACE_MAXADDR,
				/* maxsize   */	IPS_ADAPTER_INFO_LEN,
				/* numsegs   */	1,
				/* maxsegsize*/	IPS_ADAPTER_INFO_LEN,
				/* flags     */	0,
				&command->data_dmatag) != 0) {
		kprintf("ips: can't alloc dma tag for adapter status\n");
		error = ENOMEM;
		goto exit;
	}
	if (bus_dmamem_alloc(command->data_dmatag, &command->data_buffer,
	   BUS_DMA_NOWAIT, &command->data_dmamap)) {
		error = ENOMEM;
		goto exit;
	}
	command->callback = ips_wakeup_callback;
	bus_dmamap_load(command->data_dmatag, command->data_dmamap,
	    command->data_buffer, IPS_ADAPTER_INFO_LEN,
	    ips_adapter_info_callback, command, BUS_DMA_NOWAIT);
	if ((command->status.value == IPS_ERROR_STATUS) ||
	    ips_timed_wait(command, "ips", 30 * hz) != 0)
		error = ETIMEDOUT;
	if (error == 0) {
		bus_dmamap_sync(command->data_dmatag, command->data_dmamap,
		    BUS_DMASYNC_POSTREAD);
		memcpy(&(sc->adapter_info), command->data_buffer,
			IPS_ADAPTER_INFO_LEN);
	}
	bus_dmamap_unload(command->data_dmatag, command->data_dmamap);
exit:
	/* I suppose I should clean up my memory allocations */
	bus_dmamem_free(command->data_dmatag, command->data_buffer,
	    command->data_dmamap);
	bus_dma_tag_destroy(command->data_dmatag);
	ips_insert_free_cmd(sc, command);
	return error;
}

int
ips_get_adapter_info(ips_softc_t *sc)
{
	ips_command_t *command;
	int error = 0;

	if (ips_get_free_cmd(sc, &command, IPS_STATIC_FLAG) != 0) {
		device_printf(sc->dev, "unable to get adapter configuration\n");
		return ENXIO;
	}
	ips_send_adapter_info_cmd(command);
	if (COMMAND_ERROR(&command->status))
		error = ENXIO;
	return error;
}

/*
 * Below are a series of functions for sending a drive info request
 * to the adapter.  The flow order is: get, send, callback. It uses
 * the generic finish callback at the top of this file.
 * This can be used to get drive status info from the card
 */
static void
ips_drive_info_callback(void *cmdptr, bus_dma_segment_t *segments, int segnum,
			int error)
{
	ips_softc_t *sc;
	ips_command_t *command = cmdptr;
	ips_drive_cmd *command_struct;

	sc = command->sc;
	if (error) {

		command->status.value = IPS_ERROR_STATUS;
		ips_insert_free_cmd(sc, command);
		kprintf("ips: error = %d in ips_get_drive_info\n", error);
		return;
	}
	command_struct = (ips_drive_cmd *)command->command_buffer;
	command_struct->command = IPS_DRIVE_INFO_CMD;
	command_struct->id = command->id;
	command_struct->buffaddr = segments[0].ds_addr;
	bus_dmamap_sync(sc->command_dmatag, command->command_dmamap,
	    BUS_DMASYNC_PREWRITE);
	bus_dmamap_sync(command->data_dmatag, command->data_dmamap,
	    BUS_DMASYNC_PREREAD);
	sc->ips_issue_cmd(command);
}

static int
ips_send_drive_info_cmd(ips_command_t *command)
{
	int error = 0;
	ips_softc_t *sc = command->sc;
	ips_drive_info_t *driveinfo;

	if (bus_dma_tag_create(	/* parent    */	sc->adapter_dmatag,
				/* alignemnt */	1,
				/* boundary  */	0,
				/* lowaddr   */	BUS_SPACE_MAXADDR_32BIT,
				/* highaddr  */	BUS_SPACE_MAXADDR,
				/* maxsize   */	IPS_DRIVE_INFO_LEN,
				/* numsegs   */	1,
				/* maxsegsize*/	IPS_DRIVE_INFO_LEN,
				/* flags     */	0,
				&command->data_dmatag) != 0) {
		kprintf("ips: can't alloc dma tag for drive status\n");
		error = ENOMEM;
		goto exit;
	}
	if (bus_dmamem_alloc(command->data_dmatag, &command->data_buffer,
	    BUS_DMA_NOWAIT, &command->data_dmamap)) {
		error = ENOMEM;
		goto exit;
	}
	command->callback = ips_wakeup_callback;
	bus_dmamap_load(command->data_dmatag, command->data_dmamap,
	    command->data_buffer,IPS_DRIVE_INFO_LEN,
	    ips_drive_info_callback, command, BUS_DMA_NOWAIT);
	if ((command->status.value == IPS_ERROR_STATUS) ||
	    ips_timed_wait(command, "ips", 10 * hz) != 0)
		error = ETIMEDOUT;

	if (error == 0) {
		bus_dmamap_sync(command->data_dmatag, command->data_dmamap,
		    BUS_DMASYNC_POSTREAD);
		driveinfo = command->data_buffer;
		memcpy(sc->drives, driveinfo->drives, sizeof(ips_drive_t) * 8);
		sc->drivecount = driveinfo->drivecount;
		device_printf(sc->dev, "logical drives: %d\n", sc->drivecount);
	}
	bus_dmamap_unload(command->data_dmatag, command->data_dmamap);
exit:
	/* I suppose I should clean up my memory allocations */
	bus_dmamem_free(command->data_dmatag, command->data_buffer,
			command->data_dmamap);
	bus_dma_tag_destroy(command->data_dmatag);
	ips_insert_free_cmd(sc, command);
	return error;
}

int
ips_get_drive_info(ips_softc_t *sc)
{
	int error = 0;
	ips_command_t *command;

	if (ips_get_free_cmd(sc, &command, IPS_STATIC_FLAG) != 0) {
		device_printf(sc->dev, "unable to get drive configuration\n");
		return ENXIO;
	}
	ips_send_drive_info_cmd(command);
	if (COMMAND_ERROR(&command->status))
		error = ENXIO;
	return error;
}

/*
 * Below is a pair of functions for making sure data is safely
 * on disk by flushing the adapter's cache.
 */
static int
ips_send_flush_cache_cmd(ips_command_t *command)
{
	ips_softc_t *sc = command->sc;
	ips_generic_cmd *command_struct;

	PRINTF(10,"ips test: got a command, building flush command\n");
	command->callback = ips_wakeup_callback;
	command_struct = (ips_generic_cmd *)command->command_buffer;
	command_struct->command = IPS_CACHE_FLUSH_CMD;
	command_struct->id = command->id;
	bus_dmamap_sync(sc->command_dmatag, command->command_dmamap,
	    BUS_DMASYNC_PREWRITE);
	sc->ips_issue_cmd(command);
	if (command->status.value != IPS_ERROR_STATUS)
		ips_timed_wait(command, "flush2", 0);
	ips_insert_free_cmd(sc, command);
	return 0;
}

int
ips_flush_cache(ips_softc_t *sc)
{
	ips_command_t *command;

	device_printf(sc->dev, "flushing cache\n");
	if (ips_get_free_cmd(sc, &command, IPS_STATIC_FLAG) != 0) {
		device_printf(sc->dev, "ERROR: unable to get a command! "
		    "can't flush cache!\n");
		return(1);
	}
	ips_send_flush_cache_cmd(command);
	if (COMMAND_ERROR(&command->status)) {
		device_printf(sc->dev, "ERROR: cache flush command failed!\n");
		return(1);
	}
	return 0;
}

/*
 * Simplified localtime to provide timevalues for ffdc.
 * Taken from libc/stdtime/localtime.c
 */
static void
ips_ffdc_settime(ips_adapter_ffdc_cmd *command, time_t sctime)
{
	long	days, rem, y;
	int	yleap, *ip, month;
	int	year_lengths[2] = { IPS_DAYSPERNYEAR, IPS_DAYSPERLYEAR };
	int	mon_lengths[2][IPS_MONSPERYEAR] = {
		{ 31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31 },
		{ 31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31 }
	};

	days = sctime / IPS_SECSPERDAY;
	rem  = sctime % IPS_SECSPERDAY;

	command->hour = rem / IPS_SECSPERHOUR;
	rem	      = rem % IPS_SECSPERHOUR;

	command->minute = rem / IPS_SECSPERMIN;
	command->second = rem % IPS_SECSPERMIN;

	y = IPS_EPOCH_YEAR;
	while (days < 0 || days >= (long)year_lengths[yleap = ips_isleap(y)]) {
		long    newy;

		newy = y + days / IPS_DAYSPERNYEAR;
		if (days < 0)
			--newy;
		days -= (newy - y) * IPS_DAYSPERNYEAR +
		    IPS_LEAPS_THRU_END_OF(newy - 1) -
		    IPS_LEAPS_THRU_END_OF(y - 1);
		y = newy;
	}
	command->yearH = y / 100;
	command->yearL = y % 100;
	ip = mon_lengths[yleap];
	for (month = 0; days >= (long)ip[month]; ++month)
		days = days - (long)ip[month];
	command->month = month + 1;
	command->day = days + 1;
}

static int
ips_send_ffdc_reset_cmd(ips_command_t *command)
{
	ips_softc_t *sc = command->sc;
	ips_adapter_ffdc_cmd *command_struct;

	PRINTF(10, "ips test: got a command, building ffdc reset command\n");
	command->callback = ips_wakeup_callback;
	command_struct = (ips_adapter_ffdc_cmd *)command->command_buffer;
	command_struct->command = IPS_FFDC_CMD;
	command_struct->id = command->id;
	command_struct->reset_count = sc->ffdc_resetcount;
	command_struct->reset_type  = 0x0;
	ips_ffdc_settime(command_struct, sc->ffdc_resettime.tv_sec);
	bus_dmamap_sync(sc->command_dmatag, command->command_dmamap,
	    BUS_DMASYNC_PREWRITE);
	sc->ips_issue_cmd(command);
	if (command->status.value != IPS_ERROR_STATUS)
		ips_timed_wait(command, "ffdc", 0);
	ips_insert_free_cmd(sc, command);
	return 0;
}

int
ips_ffdc_reset(ips_softc_t *sc)
{
	ips_command_t *command;

	if (ips_get_free_cmd(sc, &command, IPS_STATIC_FLAG) != 0) {
		device_printf(sc->dev, "ERROR: unable to get a command! "
		    "can't send ffdc reset!\n");
		return 1;
	}
	ips_send_ffdc_reset_cmd(command);
	if (COMMAND_ERROR(&command->status)) {
		/*
		 * apparently some cards may report error status for
		 * an ffdc reset command, even though it works correctly
		 * afterwards.  just complain about that and proceed here.
		 */
		device_printf(sc->dev,
			      "ERROR: ffdc reset command failed(0x%04x)!\n",
			      command->status.value);
	}
	return 0;
}

static void
ips_write_nvram(ips_command_t *command)
{
	ips_softc_t *sc = command->sc;
	ips_rw_nvram_cmd *command_struct;
	ips_nvram_page5 *nvram;

	/*FIXME check for error */
	command->callback = ips_wakeup_callback;
	command_struct = (ips_rw_nvram_cmd *)command->command_buffer;
	command_struct->command = IPS_RW_NVRAM_CMD;
	command_struct->id = command->id;
	command_struct->pagenum = 5;
	command_struct->rw	= 1;	/* write */
	bus_dmamap_sync(command->data_dmatag, command->data_dmamap,
	    BUS_DMASYNC_POSTREAD);
	nvram = command->data_buffer;
	/* retrieve adapter info and save in sc */
	sc->adapter_type = nvram->adapter_type;
	strncpy(nvram->driver_high, IPS_VERSION_MAJOR, 4);
	strncpy(nvram->driver_low, IPS_VERSION_MINOR, 4);
	nvram->operating_system = IPS_OS_FREEBSD;
	bus_dmamap_sync(sc->command_dmatag, command->command_dmamap,
	    BUS_DMASYNC_PREWRITE);
	sc->ips_issue_cmd(command);
}

static void
ips_read_nvram_callback(void *cmdptr, bus_dma_segment_t *segments, int segnum,
			int error)
{
	ips_softc_t *sc;
	ips_command_t *command = cmdptr;
	ips_rw_nvram_cmd *command_struct;

	sc = command->sc;
	if (error) {
		command->status.value = IPS_ERROR_STATUS;
		ips_insert_free_cmd(sc, command);
		kprintf("ips: error = %d in ips_read_nvram_callback\n", error);
		return;
	}
	command_struct = (ips_rw_nvram_cmd *)command->command_buffer;
	command_struct->command = IPS_RW_NVRAM_CMD;
	command_struct->id = command->id;
	command_struct->pagenum = 5;
	command_struct->rw = 0;
	command_struct->buffaddr = segments[0].ds_addr;

	bus_dmamap_sync(sc->command_dmatag, command->command_dmamap,
	    BUS_DMASYNC_PREWRITE);
	bus_dmamap_sync(command->data_dmatag, command->data_dmamap,
	    BUS_DMASYNC_PREREAD);
	sc->ips_issue_cmd(command);
}

static int
ips_read_nvram(ips_command_t *command)
{
	int error = 0;
	ips_softc_t *sc = command->sc;

	if (bus_dma_tag_create(	/* parent    */	sc->adapter_dmatag,
				/* alignemnt */	1,
				/* boundary  */	0,
				/* lowaddr   */	BUS_SPACE_MAXADDR_32BIT,
				/* highaddr  */	BUS_SPACE_MAXADDR,
				/* maxsize   */	IPS_NVRAM_PAGE_SIZE,
				/* numsegs   */	1,
				/* maxsegsize*/	IPS_NVRAM_PAGE_SIZE,
				/* flags     */	0,
				&command->data_dmatag) != 0) {
		kprintf("ips: can't alloc dma tag for nvram\n");
		error = ENOMEM;
		goto exit;
	}
	if (bus_dmamem_alloc(command->data_dmatag, &command->data_buffer,
	    BUS_DMA_NOWAIT, &command->data_dmamap)) {
		error = ENOMEM;
		goto exit;
	}
	command->callback = ips_write_nvram;
	bus_dmamap_load(command->data_dmatag, command->data_dmamap,
	    command->data_buffer, IPS_NVRAM_PAGE_SIZE, ips_read_nvram_callback,
	    command, BUS_DMA_NOWAIT);
	if ((command->status.value == IPS_ERROR_STATUS) ||
	    ips_timed_wait(command, "ips", 0) != 0)
		error = ETIMEDOUT;
	if (error == 0) {
		bus_dmamap_sync(command->data_dmatag, command->data_dmamap,
				BUS_DMASYNC_POSTWRITE);
	}
	bus_dmamap_unload(command->data_dmatag, command->data_dmamap);
exit:
	bus_dmamem_free(command->data_dmatag, command->data_buffer,
			command->data_dmamap);
	bus_dma_tag_destroy(command->data_dmatag);
	ips_insert_free_cmd(sc, command);
	return error;
}

int
ips_update_nvram(ips_softc_t *sc)
{
	ips_command_t *command;

	if (ips_get_free_cmd(sc, &command, IPS_STATIC_FLAG) != 0) {
		device_printf(sc->dev, "ERROR: unable to get a command! "
		    "can't update nvram\n");
		return 1;
	}
	ips_read_nvram(command);
	if (COMMAND_ERROR(&command->status)) {
		device_printf(sc->dev, "ERROR: nvram update command failed!\n");
		return 1;
	}
	return 0;
}

static int
ips_send_config_sync_cmd(ips_command_t *command)
{
	ips_softc_t *sc = command->sc;
	ips_generic_cmd *command_struct;

	PRINTF(10, "ips test: got a command, building flush command\n");
	command->callback = ips_wakeup_callback;
	command_struct = (ips_generic_cmd *)command->command_buffer;
	command_struct->command = IPS_CONFIG_SYNC_CMD;
	command_struct->id = command->id;
	command_struct->reserve2 = IPS_POCL;
	bus_dmamap_sync(sc->command_dmatag, command->command_dmamap,
	    BUS_DMASYNC_PREWRITE);
	sc->ips_issue_cmd(command);
	if (command->status.value != IPS_ERROR_STATUS)
		ips_timed_wait(command, "ipssyn", 0);
	ips_insert_free_cmd(sc, command);
	return 0;
}

static int
ips_send_error_table_cmd(ips_command_t *command)
{
	ips_softc_t *sc = command->sc;
	ips_generic_cmd *command_struct;

	PRINTF(10, "ips test: got a command, building errortable command\n");
	command->callback = ips_wakeup_callback;
	command_struct = (ips_generic_cmd *)command->command_buffer;
	command_struct->command = IPS_ERROR_TABLE_CMD;
	command_struct->id = command->id;
	command_struct->reserve2 = IPS_CSL;
	bus_dmamap_sync(sc->command_dmatag, command->command_dmamap,
	    BUS_DMASYNC_PREWRITE);
	sc->ips_issue_cmd(command);
	if (command->status.value != IPS_ERROR_STATUS)
		ips_timed_wait(command, "ipsetc", 0);
	ips_insert_free_cmd(sc, command);
	return 0;
}

int
ips_clear_adapter(ips_softc_t *sc)
{
	ips_command_t *command;

	device_printf(sc->dev, "syncing config\n");
	if (ips_get_free_cmd(sc, &command, IPS_STATIC_FLAG) != 0) {
		device_printf(sc->dev, "ERROR: unable to get a command! "
		    "can't sync cache!\n");
		return 1;
	}
	ips_send_config_sync_cmd(command);
	if (COMMAND_ERROR(&command->status)) {
		device_printf(sc->dev, "ERROR: cache sync command failed!\n");
		return 1;
	}
	device_printf(sc->dev, "clearing error table\n");
	if (ips_get_free_cmd(sc, &command, IPS_STATIC_FLAG) != 0) {
		device_printf(sc->dev, "ERROR: unable to get a command! "
		    "can't sync cache!\n");
		return 1;
	}
	ips_send_error_table_cmd(command);
	if (COMMAND_ERROR(&command->status)) {
		device_printf(sc->dev, "ERROR: etable command failed!\n");
		return 1;
	}
	return 0;
}
