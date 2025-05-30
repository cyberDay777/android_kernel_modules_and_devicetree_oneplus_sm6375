// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2018-2020 Oplus. All rights reserved.
 */

#include <linux/of_gpio.h>
#include <linux/delay.h>
#include <linux/sysfs.h>
#include <asm/uaccess.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/hrtimer.h>
#include <linux/kthread.h>
#include <linux/random.h>
#include <linux/slab.h>
#include <linux/sched.h>
#include <linux/sched/rt.h>
#include <linux/task_work.h>
#include <linux/pinctrl/consumer.h>
#include <linux/pinctrl/pinctrl.h>
#include <linux/pinctrl/machine.h>
#include <linux/regulator/consumer.h>

#include "sec_drivers_s6sy791.h"

/****************** Start of Log Tag Declear and level define*******************************/
#ifdef TPD_DEVICE
#undef TPD_DEVICE
#define TPD_DEVICE "sec-s6sy791"
#else
#define TPD_DEVICE "sec-s6sy791"
#endif
/******************** End of Log Tag Declear and level define*********************************/

/*************************** start of function delcare****************************************/
static void sec_mdelay(unsigned int ms);
static int sec_reset(void *chip_data);
static int sec_power_control(void *chip_data, bool enable);
static int sec_get_verify_result(struct chip_data_s6sy791 *chip_info);
static int sec_read_mutual(struct chip_data_s6sy791 *chip_info, u8 type,
		char *data, int len);
static bool check_calibration(struct chip_data_s6sy791 *chip_info);
static int ver_bottom_large_handle_func(struct chip_data_s6sy791 *chip_info,
		struct grip_zone_area *grip_zone, bool enable);
static int hor_corner_large_handle_func(struct chip_data_s6sy791 *chip_info,
		struct grip_zone_area *grip_zone, bool enable);
static int long_size_dead_zone_handle_func(struct chip_data_s6sy791 *chip_info,
		struct grip_zone_area *grip_zone, bool enable);
static int short_size_dead_zone_handle_func(struct chip_data_s6sy791 *chip_info,
		struct grip_zone_area *grip_zone, bool enable);
static int long_size_condtion_zone_handle_func(
		struct chip_data_s6sy791 *chip_info,
		struct grip_zone_area *grip_zone, bool enable);

static int short_size_condtion_zone_handle_func(
		struct chip_data_s6sy791 *chip_info,
		struct grip_zone_area *grip_zone, bool enable);

static int long_size_large_zone_handle_func(struct chip_data_s6sy791 *chip_info,
		struct grip_zone_area *grip_zone, bool enable);
static int short_size_large_zone_handle_func(
		struct chip_data_s6sy791 *chip_info,
		struct grip_zone_area *grip_zone, bool enable);

static int sec_set_large_corner_frame_limit(void *chip_data, int frame_limit);
static int sec_set_no_handle_area(void *chip_data,
		struct kernel_grip_info *grip_info);
static int sec_set_condition_frame_limit(void *chip_data, int frame_limit);
static int sec_set_large_frame_limit(void *chip_data, int frame_limit);
static void sec_set_grip_touch_direction(void *chip_data, uint8_t dir);


/**************************** end of function delcare*****************************************/

/*************************** start of global variable delcare****************************************/
static struct sec_support_grip_zone sec_grip[] = {
	{"ver_left_bottom_large", ver_bottom_large_handle_func},
	/*{"ver_right_bottom_large", ver_bottom_large_handle_func},*/
	{"hor90_left_corner_large", hor_corner_large_handle_func},
	/*{"hor90_right_corner_large", hor_corner_large_handle_func},*/
	/*{"hor270_left_corner_large", hor_corner_large_handle_func},*/
	/*{"hor270_right_corner_large", hor_corner_large_handle_func},*/
	{"ver_left_dead", long_size_dead_zone_handle_func},
	/*{"ver_right_dead", long_size_dead_zone_handle_func},*/
	{"hor_left_dead", short_size_dead_zone_handle_func},
	/*{"hor_right_dead", short_size_dead_zone_handle_func},*/
	{"ver_left_condtion", long_size_condtion_zone_handle_func},
	/*{"ver_right_condtion", long_size_condtion_zone_handle_func},*/
	{"hor_left_condtion", short_size_condtion_zone_handle_func},
	/*{"hor_right_condtion", short_size_condtion_zone_handle_func},*/
	{"ver_left_large", long_size_large_zone_handle_func},
	/*{"ver_right_large", long_size_large_zone_handle_func},*/
	{"hor_left_large", short_size_large_zone_handle_func},
	/*{"hor_right_large", short_size_large_zone_handle_func},*/
};
/**************************** end of global variable delcare*****************************************/

/****** Start of other functions that work for oplus_touchpanel_operations callbacks***********/
static int sec_enable_black_gesture(struct chip_data_s6sy791 *chip_info,
		int enable)
{
	int ret = 0;
	int i = 0;

	TPD_INFO("%s, enable = %d\n", __func__, enable);

	if (enable) {
		touch_i2c_write_word(chip_info->client, SEC_CMD_WAKEUP_GESTURE_MODE, 0xFF1F);

		for (i = 0; i < 20; i++) {
			touch_i2c_write_byte(chip_info->client, SEC_CMD_SET_POWER_MODE, 0x01);
			sec_mdelay(10);
			ret = touch_i2c_read_byte(chip_info->client, SEC_CMD_SET_POWER_MODE);

			if (0x01 == ret) {
				break;
			}
		}

#ifdef CONFIG_OPLUS_TP_APK

		if (chip_info->debug_gesture_sta) {
			chip_info->in_gesture = true;
			chip_info->geture_points_count = 0;
			chip_info->debug_gesture_type = 0;
			touch_i2c_write_byte(chip_info->client, SEC_CMD_GESTURE_DEBUG, 0x01);
		}

#endif /* end of CONFIG_OPLUS_TP_APK*/

	} else {
		touch_i2c_write_word(chip_info->client, SEC_CMD_WAKEUP_GESTURE_MODE, 0x0000);

		if (chip_info->fp_info.touch_state != FINGERPRINT_DOWN_DETECT
				|| *chip_info->in_suspend) {
			for (i = 0; i < 20; i++) {
				touch_i2c_write_byte(chip_info->client, SEC_CMD_SET_POWER_MODE, 0x00);
				sec_mdelay(10);
				ret = touch_i2c_read_byte(chip_info->client, SEC_CMD_SET_POWER_MODE);

				if (0x00 == ret) {
					break;
				}
			}
		}

#ifdef CONFIG_OPLUS_TP_APK

		if (chip_info->debug_gesture_sta) {
			chip_info->in_gesture = false;
			touch_i2c_write_byte(chip_info->client, SEC_CMD_GESTURE_DEBUG, 0x00);
		}

#endif /* end of CONFIG_OPLUS_TP_APK*/
	}

	if (i >= 20) {
		ret = -1;
		TPD_INFO("%s: change black gesture failed\n", __func__);

	} else {
		TPD_INFO("%s: %d times change black gesture success\n", __func__, i);
	}

	return ret;
}

static void sec_enable_gesture_mask(void *chip_data, uint32_t enable)
{
	struct chip_data_s6sy791 *chip_info = (struct chip_data_s6sy791 *)chip_data;
	int ret = -1;
	int i = 0;

	TPD_INFO("%s, enable = %d\n", __func__, enable);

	if (enable) {
		for (i = 0; i < 20; i++) {
			touch_i2c_write_word(chip_info->client, SEC_CMD_WAKEUP_GESTURE_MODE, 0xFF1F);
			touch_i2c_write_byte(chip_info->client, SEC_CMD_SET_POWER_MODE, 0x01);
			sec_mdelay(10);
			ret = touch_i2c_read_byte(chip_info->client, SEC_CMD_SET_POWER_MODE);

			if (0x01 == ret) {
				break;
			}
		}

	} else {
		touch_i2c_write_word(chip_info->client, SEC_CMD_WAKEUP_GESTURE_MODE, 0x0000);
		return;
	}

	if (i >= 20) {
		ret = -1;
		TPD_INFO("%s: change black gesture_mask failed\n", __func__);

	} else {
		TPD_INFO("%s: %d times change black gesture_mask success\n", __func__, i);
	}
}


static int sec_enable_charge_mode(struct chip_data_s6sy791 *chip_info,
		int enable)
{
	int ret = -1;

	if (enable) {
		ret = touch_i2c_write_byte(chip_info->client, SET_CMD_SET_CHARGER_MODE, 0x02);

	} else {
		ret = touch_i2c_write_byte(chip_info->client, SET_CMD_SET_CHARGER_MODE, 0x01);
	}

	TPD_INFO("%s: state: %d %s!\n", __func__, enable,
			ret < 0 ? "failed" : "success");
	return ret;
}

static int sec_enable_palm_reject(struct chip_data_s6sy791 *chip_info,
		int enable)
{
	int ret = -1;

	if (enable) {
		ret = touch_i2c_write_word(chip_info->client, SEC_CMD_PALM_SWITCH, 0x0061);

	} else {
		ret = touch_i2c_write_word(chip_info->client, SEC_CMD_PALM_SWITCH, 0x0041);
	}

	TPD_INFO("%s: state: %d %s!\n", __func__, enable,
			ret < 0 ? "failed" : "success");
	return ret;
}

static int sec_enable_game_mode(struct chip_data_s6sy791 *chip_info, int enable)
{
	int ret = -1;
	char buf[4] = {0x00, 0x00, 0x00, 0x00};

	buf[3] = enable ? 0x12 : 0x18;  /*default value 0x18*/
	ret = touch_i2c_write_block(chip_info->client, SEC_CMD_SENSETIVE_CTRL,
			sizeof(buf), buf);
	ret |= touch_i2c_write_byte(chip_info->client, SEC_CMD_GAME_MODE,
			enable ? 1 : 0);
	TPD_INFO("%s: state: %d %s!\n", __func__, enable,
			ret < 0 ? "failed" : "success");
	return ret;
}

static int sec_enable_headset_mode(struct chip_data_s6sy791 *chip_info,
		int enable)
{
	int ret = -1;

	ret = touch_i2c_write_byte(chip_info->client, SEC_CMD_HEADSET_MODE,
			enable ? 1 : 0);
	TPD_INFO("%s: state: %d %s!\n", __func__, enable,
			ret < 0 ? "failed" : "success");
	return ret;
}

static void sec_mdelay(unsigned int ms)
{
	if (ms < 20) {
		usleep_range(ms * 1000, ms * 1000);

	} else {
		msleep(ms);
	}
}

static int sec_wait_for_ready(struct chip_data_s6sy791 *chip_info,
		unsigned int ack)
{
	int rc = -1;
	int retry = 0, retry_cnt = 100;
	int8_t status = -1;
	u8 tBuff[SEC_EVENT_BUFF_SIZE] = {0};

	while (touch_i2c_read_block(chip_info->client, SEC_READ_ONE_EVENT,
				SEC_EVENT_BUFF_SIZE, tBuff) > 0) {
		status = (tBuff[0] >> 2) & 0xF;

		if ((status == TYPE_STATUS_EVENT_INFO)
				|| (status == TYPE_STATUS_EVENT_VENDOR_INFO)) {
			if (tBuff[1] == ack) {
				rc = 0;
				break;
			}
		}

		if (retry++ > retry_cnt) {
			TPD_INFO("%s: Time Over, event_buf: %02X, %02X, %02X, %02X, %02X, %02X, %02X, %02X \n",
					\
					__func__, tBuff[0], tBuff[1], tBuff[2], tBuff[3], tBuff[4], tBuff[5], tBuff[6],
					tBuff[7]);
			break;
		}

		sec_mdelay(20);
	}

	return rc;
}

static int sec_enter_fw_mode(struct chip_data_s6sy791 *chip_info)
{
	int ret = -1;
	u8 device_id[3] = {0};
	u8 fw_update_mode_passwd[] = {0x55, 0xAC};

	ret = touch_i2c_write_block(chip_info->client, SEC_CMD_ENTER_FW_MODE,
			sizeof(fw_update_mode_passwd), fw_update_mode_passwd);
	sec_mdelay(20);

	if (ret < 0) {
		TPD_INFO("%s: write cmd to enter fw mode failed\n", __func__);
		return -1;
	}

	/*need soft reset or hard reset*/
	if (gpio_is_valid(chip_info->hw_res->reset_gpio)) {
		gpio_direction_output(chip_info->hw_res->reset_gpio, false);
		sec_mdelay(10);
		gpio_direction_output(chip_info->hw_res->reset_gpio, true);

	} else {
		ret = touch_i2c_write_block(chip_info->client, SEC_CMD_SOFT_RESET, 0, NULL);

		if (ret < 0) {
			TPD_INFO("%s: write soft reset failed\n", __func__);
			return -1;
		}
	}

	sec_mdelay(100);

	ret = touch_i2c_read_byte(chip_info->client,
			SEC_READ_BOOT_STATUS);     /*after reset, check bootloader again*/

	if (ret < 0) {
		TPD_INFO("%s: read boot status failed\n", __func__);
		return -1;
	}

	if (ret != SEC_STATUS_BOOT_MODE) {
		TPD_INFO("%s: read boot status, but no in boot mode(%d)\n", __func__, ret);
		return -1;
	}

	sec_mdelay(10);

	ret = touch_i2c_read_block(chip_info->client, SEC_READ_ID, 3, device_id);

	if (ret < 0) {
		TPD_INFO("%s: read 3 byte device id failed\n", __func__);
		return -1;
	}

	chip_info->boot_ver[0] = device_id[0];
	chip_info->boot_ver[1] = device_id[1];
	chip_info->boot_ver[2] = device_id[2];
	chip_info->flash_page_size = 512;
	/* The ic is 791 so it must be 0x91.*/
	/*if ((device_id[1] == 0x37) && (device_id[2] == 0x91))*/
	/*    chip_info->flash_page_size = 512;*/

	return 0;
}

static u8 sec_checksum(u8 *data, int offset, int size)
{
	int i;
	u8 checksum = 0;

	for (i = 0; i < size; i++) {
		checksum += data[i + offset];
	}

	return checksum;
}

static int sec_flash_page_erase(struct chip_data_s6sy791 *chip_info,
		u32 page_idx, u32 page_num)
{
	int ret = -1;
	u8 tCmd[6] = {0};

	tCmd[0] = SEC_CMD_FLASH_ERASE;
	tCmd[1] = (u8)((page_idx >> 8) & 0xFF);
	tCmd[2] = (u8)((page_idx >> 0) & 0xFF);
	tCmd[3] = (u8)((page_num >> 8) & 0xFF);
	tCmd[4] = (u8)((page_num >> 0) & 0xFF);
	tCmd[5] = sec_checksum(tCmd, 1, 4);

	ret = touch_i2c_write(chip_info->client, tCmd, 6);

	return ret;
}

static int sec_flash_page_write(struct chip_data_s6sy791 *chip_info,
		u32 page_idx, u8 *page_data)
{
	int ret;
	u8 tCmd[1 + 2 + SEC_FW_BLK_SIZE_MAX + 1];
	int flash_page_size = (int)chip_info->flash_page_size;

	tCmd[0] = SEC_CMD_FLASH_WRITE;
	tCmd[1] = (u8)((page_idx >> 8) & 0xFF);
	tCmd[2] = (u8)((page_idx >> 0) & 0xFF);

	memcpy(&tCmd[3], page_data, flash_page_size);
	tCmd[1 + 2 + flash_page_size] = sec_checksum(tCmd, 1, 2 + flash_page_size);

	ret = touch_i2c_write(chip_info->client, tCmd, 1 + 2 + flash_page_size + 1);
	return ret;
}

static bool sec_limited_flash_page_write(struct chip_data_s6sy791 *chip_info,
		u32 page_idx, u8 *page_data)
{
	int ret = -1;
	u8 *tCmd = NULL;
	u8 copy_data[3 + SEC_FW_BLK_SIZE_MAX];
	int copy_left = (int)chip_info->flash_page_size + 3;
	int copy_size = 0;
	int copy_max = I2C_BURSTMAX - 1;
	int flash_page_size = (int)chip_info->flash_page_size;

	copy_data[0] = (u8)((page_idx >> 8) & 0xFF);    /* addH */
	copy_data[1] = (u8)((page_idx >> 0) & 0xFF);    /* addL */

	memcpy(&copy_data[2], page_data, flash_page_size);    /* DATA */
	copy_data[2 + flash_page_size] = sec_checksum(copy_data, 0,
			2 + flash_page_size);    /* CS */

	while (copy_left > 0) {
		int copy_cur = (copy_left > copy_max) ? copy_max : copy_left;

		tCmd = tp_devm_kzalloc(&chip_info->client->dev, copy_cur + 1, GFP_KERNEL);

		if (!tCmd) {
			goto err_write;
		}

		if (copy_size == 0) {
			tCmd[0] = SEC_CMD_FLASH_WRITE;

		} else {
			tCmd[0] = SEC_CMD_FLASH_PADDING;
		}

		memcpy(&tCmd[1], &copy_data[copy_size], copy_cur);

		ret = touch_i2c_write(chip_info->client, tCmd, 1 + copy_cur);

		if (ret < 0) {
			ret = touch_i2c_write(chip_info->client, tCmd, 1 + copy_cur);

			if (ret < 0) {
				TPD_INFO("%s: failed, ret:%d\n", __func__, ret);
			}
		}

		copy_size += copy_cur;
		copy_left -= copy_cur;

		tp_devm_kfree(&chip_info->client->dev, (void **)&tCmd, copy_cur + 1);
	}

	return ret;

err_write:
	TPD_INFO("%s: failed to alloc.\n", __func__);
	return -ENOMEM;
}

static int sec_flash_write(struct chip_data_s6sy791 *chip_info, u32 mem_addr,
		u8 *mem_data, u32 mem_size)
{
	int ret = -1;
	u32 page_idx = 0, size_copy = 0, flash_page_size = 0;
	u32 page_idx_start = 0, page_idx_end = 0, page_num = 0;
	u8 page_buf[SEC_FW_BLK_SIZE_MAX] = {0};

	if (mem_size == 0) {
		return 0;
	}

	flash_page_size = chip_info->flash_page_size;
	page_idx_start = mem_addr / flash_page_size;
	page_idx_end = (mem_addr + mem_size - 1) / flash_page_size;
	page_num = page_idx_end - page_idx_start + 1;

	ret = sec_flash_page_erase(chip_info, page_idx_start, page_num);

	if (ret < 0) {
		TPD_INFO("%s: fw erase failed, mem_addr= %08X, pagenum = %d\n", __func__,
				mem_addr, page_num);
		return -EIO;
	}

	sec_mdelay(page_num + 10);

	size_copy = mem_size % flash_page_size;

	if (size_copy == 0) {
		size_copy = flash_page_size;
	}

	memset(page_buf, 0, flash_page_size);

	for (page_idx = page_num - 1;; page_idx--) {
		memcpy(page_buf, mem_data + (page_idx * flash_page_size), size_copy);

		if (chip_info->boot_ver[0] == 0xB2) {
			ret = sec_flash_page_write(chip_info, (page_idx + page_idx_start), page_buf);

			if (ret < 0) {
				sec_mdelay(50);
				ret = sec_flash_page_write(chip_info, (page_idx + page_idx_start), page_buf);

				if (ret < 0) {
					TPD_INFO("%s: fw write failed, page_idx = %u\n", __func__, page_idx);
					goto err;
				}
			}

		} else {
			ret = sec_limited_flash_page_write(chip_info, (page_idx + page_idx_start),
					page_buf);

			if (ret < 0) {
				sec_mdelay(50);
				ret = sec_limited_flash_page_write(chip_info, (page_idx + page_idx_start),
						page_buf);

				if (ret < 0) {
					TPD_INFO("%s: fw write failed, page_idx = %u\n", __func__, page_idx);
					goto err;
				}
			}
		}

		size_copy = flash_page_size;
		sec_mdelay(5);

		if (page_idx ==
				0) { /* end condition (page_idx >= 0)   page_idx type unsinged int */
			break;
		}
	}

	return mem_size;
err:
	return -EIO;
}

static int sec_block_read(struct chip_data_s6sy791 *chip_info, u32 mem_addr,
		int mem_size, u8 *buf)
{
	int ret;
	u8 cmd[5];
	u8 *data;

	if (mem_size >= 64 * 1024) {
		TPD_INFO("%s: mem size over 64K\n", __func__);
		return -EIO;
	}

	cmd[0] = (u8)SEC_CMD_FLASH_READ_ADDR;
	cmd[1] = (u8)((mem_addr >> 24) & 0xff);
	cmd[2] = (u8)((mem_addr >> 16) & 0xff);
	cmd[3] = (u8)((mem_addr >> 8) & 0xff);
	cmd[4] = (u8)((mem_addr >> 0) & 0xff);

	ret = touch_i2c_write(chip_info->client, cmd, 5);

	if (ret < 0) {
		TPD_INFO("%s: send command failed, %02X\n", __func__, cmd[0]);
		return -EIO;
	}

	udelay(10);
	cmd[0] = (u8)SEC_CMD_FLASH_READ_SIZE;
	cmd[1] = (u8)((mem_size >> 8) & 0xff);
	cmd[2] = (u8)((mem_size >> 0) & 0xff);

	ret = touch_i2c_write(chip_info->client, cmd, 3);

	if (ret < 0) {
		TPD_INFO("%s: send command failed, %02X\n", __func__, cmd[0]);
		return -EIO;
	}

	udelay(10);
	cmd[0] = (u8)SEC_CMD_FLASH_READ_DATA;
	data = buf;

	ret = touch_i2c_read(chip_info->client, cmd, 1, data, mem_size);

	if (ret < 0) {
		TPD_INFO("%s: memory read failed\n", __func__);
		return -EIO;
	}

	return 0;
}

static int sec_memory_read(struct chip_data_s6sy791 *chip_info, u32 mem_addr,
		u8 *mem_data, u32 mem_size)
{
	int ret;
	int retry = 3;
	int read_size = 0;
	int unit_size;
	int max_size = I2C_BURSTMAX;
	int read_left = (int)mem_size;
	u8 *tmp_data;

	tmp_data = tp_devm_kzalloc(&chip_info->client->dev, max_size, GFP_KERNEL);

	if (!tmp_data) {
		TPD_INFO("%s: failed to kmalloc\n", __func__);
		return -ENOMEM;
	}

	while (read_left > 0) {
		unit_size = (read_left > max_size) ? max_size : read_left;
		retry = 3;

		do {
			ret = sec_block_read(chip_info, mem_addr, unit_size, tmp_data);

			if (retry-- == 0) {
				TPD_INFO("%s: fw read fail mem_addr=%08X, unit_size=%d\n", __func__, mem_addr,
						unit_size);
				kfree(tmp_data);
				return -1;
			}

			memcpy(mem_data + read_size, tmp_data, unit_size);
		} while (ret < 0);

		mem_addr += unit_size;
		read_size += unit_size;
		read_left -= unit_size;
	}

	tp_devm_kfree(&chip_info->client->dev, (void **)&tmp_data, max_size);

	return read_size;
}

static int sec_chunk_update(struct chip_data_s6sy791 *chip_info, u32 addr,
		u32 size, u8 *data)
{
	int ii = 0, ret = 0;
	u8 *mem_rb = NULL;
	u32 write_size = 0;
	u32 fw_size = size;

	write_size = sec_flash_write(chip_info, addr, data, fw_size);

	if (write_size != fw_size) {
		TPD_INFO("%s: fw write failed\n", __func__);
		ret = -1;
		goto err_write_fail;
	}

	mem_rb = tp_vzalloc(fw_size);

	if (!mem_rb) {
		TPD_INFO("%s: vzalloc failed\n", __func__);
		ret = -1;
		goto err_write_fail;
	}

	if (sec_memory_read(chip_info, addr, mem_rb, fw_size) >= 0) {
		for (ii = 0; ii < fw_size; ii++) {
			if (data[ii] != mem_rb[ii]) {
				break;
			}
		}

		if (fw_size != ii) {
			TPD_INFO("%s: fw verify fail at data[%d](%d, %d)\n", __func__, ii, data[ii],
					mem_rb[ii]);
			ret = -1;
			goto out;
		}

	} else {
		ret = -1;
		goto out;
	}

	TPD_INFO("%s: verify done(%d)\n", __func__, ret);

out:
	tp_vfree((void **)&mem_rb);
err_write_fail:
	sec_mdelay(10);

	return ret;
}

static int sec_read_calibration_report(struct chip_data_s6sy791 *chip_info)
{
	int ret;
	u8 buf[5] = { 0 };

	buf[0] = SEC_CMD_READ_CALIBRATION_REPORT;

	ret = touch_i2c_read(chip_info->client, &buf[0], 1, &buf[1], 4);

	if (ret < 0) {
		TPD_INFO("%s: failed to read, ret = %d\n", __func__, ret);
		return ret;
	}

	TPD_INFO("%s: count:%d, pass count:%d, fail count:%d, status:0x%X\n",
			__func__, buf[1], buf[2], buf[3], buf[4]);

	return buf[4];
}

static int sec_execute_force_calibration(struct chip_data_s6sy791 *chip_info)
{
	int rc = -1;

	TPD_INFO("start do force calibration\n");

	if (touch_i2c_write_block(chip_info->client, SEC_CMD_FACTORY_PANELCALIBRATION,
				0, NULL) < 0) {
		TPD_INFO("%s: Write Cal commend failed!\n", __func__);
		return rc;
	}

	sec_mdelay(1000);
	rc = sec_wait_for_ready(chip_info, SEC_VENDOR_ACK_OFFSET_CAL_DONE);

	return rc;
}

static void handleFourCornerPoint(struct Coordinate *point, int n)
{
	int i = 0;
	struct Coordinate left_most = point[0], right_most = point[0],
	top_most = point[0], down_most = point[0];

	if (n < 4) {
		return;
	}

	for (i = 0; i < n; i++) {
		if (right_most.x < point[i].x) {   /*xmax*/
			right_most = point[i];
		}

		if (left_most.x > point[i].x) {   /*xmin*/
			left_most = point[i];
		}

		if (down_most.y < point[i].y) {   /*ymax*/
			down_most = point[i];
		}

		if (top_most.y > point[i].y) {   /*ymin*/
			top_most = point[i];
		}
	}

	point[0] = top_most;
	point[1] = left_most;
	point[2] = down_most;
	point[3] = right_most;
}
/****** End of other functions that work for oplus_touchpanel_operations callbacks*************/

/********* Start of implementation of oplus_touchpanel_operations callbacks********************/
static int sec_reset(void *chip_data)
{
	int ret = -1;
	struct chip_data_s6sy791 *chip_info = (struct chip_data_s6sy791 *)chip_data;

	TPD_INFO("%s is called\n", __func__);

	if (chip_info->is_power_down) { /*power off state, no need reset*/
		return 0;
	}

	disable_irq_nosync(chip_info->client->irq);

	if (gpio_is_valid(chip_info->hw_res->reset_gpio)) {    /*rsted by rst pin*/
		TPD_INFO("reset by pull down rst pin");
		gpio_direction_output(chip_info->hw_res->reset_gpio, false);
		sec_mdelay(5);
		gpio_direction_output(chip_info->hw_res->reset_gpio, true);

	} else {    /*otherwise by soft reset*/
		touch_i2c_write_block(chip_info->client, SEC_CMD_SOFT_RESET, 0, NULL);
	}

	sec_mdelay(RESET_TO_NORMAL_TIME);
	sec_wait_for_ready(chip_info, SEC_ACK_BOOT_COMPLETE);
	ret = touch_i2c_write_block(chip_info->client, SEC_CMD_SENSE_ON, 0, NULL);
	TPD_INFO("%s: write sense on %s\n", __func__, (ret < 0) ? "failed" : "success");

	enable_irq(chip_info->client->irq);

	return 0;
}

static int sec_ftm_process(void *chip_data)
{
	struct chip_data_s6sy791 *chip_info = (struct chip_data_s6sy791 *)chip_data;

	TPD_INFO("%s is called!\n", __func__);
	tp_powercontrol_avdd(chip_info->hw_res, false);
	tp_powercontrol_vddi(chip_info->hw_res, false);

	if (gpio_is_valid(chip_info->hw_res->reset_gpio)) {
		gpio_direction_output(chip_info->hw_res->reset_gpio, false);
	}

	return 0;
}

static int sec_get_vendor(void *chip_data, struct panel_info *panel_data)
{
	int len = 0;
	char manu_temp[MAX_DEVICE_MANU_LENGTH] = "SEC_";
	struct chip_data_s6sy791 *chip_info = (struct chip_data_s6sy791 *)chip_data;

	len = strlen(panel_data->fw_name);

	if ((len > 3) && (panel_data->fw_name[len - 3] == 'i') && \
			(panel_data->fw_name[len - 2] == 'm')
			&& (panel_data->fw_name[len - 1] == 'g')) {
		panel_data->fw_name[len - 3] = 'b';
		panel_data->fw_name[len - 2] = 'i';
		panel_data->fw_name[len - 1] = 'n';
	}

	chip_info->tp_type = panel_data->tp_type;
	strlcat(manu_temp, panel_data->manufacture_info.manufacture,
			MAX_DEVICE_MANU_LENGTH);
	strncpy(panel_data->manufacture_info.manufacture, manu_temp,
			MAX_DEVICE_MANU_LENGTH);
	TPD_INFO("chip_info->tp_type = %d, panel_data->fw_name = %s\n",
			chip_info->tp_type, panel_data->fw_name);

	return 0;
}

static int sec_get_chip_info(void *chip_data)
{
	return 0;
}

static int sec_power_control(void *chip_data, bool enable)
{
	int ret = 0;
	struct chip_data_s6sy791 *chip_info = (struct chip_data_s6sy791 *)chip_data;

	TPD_INFO("%s enable :%d\n", __func__, enable);

	if (true == enable) {
		tp_powercontrol_vddi(chip_info->hw_res, true);
		sec_mdelay(1);
		tp_powercontrol_avdd(chip_info->hw_res, true);

		if (gpio_is_valid(chip_info->hw_res->reset_gpio)) {
			TPD_INFO("Set the reset_gpio 1\n");
			gpio_direction_output(chip_info->hw_res->reset_gpio, 1);
		}

		msleep(RESET_TO_NORMAL_TIME);
		sec_wait_for_ready(chip_info, SEC_ACK_BOOT_COMPLETE);
		ret = touch_i2c_write_block(chip_info->client, SEC_CMD_SENSE_ON, 0, NULL);
		TPD_INFO("%s: write sense on %s\n", __func__, (ret < 0) ? "failed" : "success");
		chip_info->is_power_down = false;

		if (chip_info->irq_requested) {
			enable_irq(chip_info->client->irq);
		}

	} else {
		if (chip_info->irq_requested) {
			disable_irq_nosync(chip_info->client->irq);
		}

		if (gpio_is_valid(chip_info->hw_res->reset_gpio)) {
			TPD_INFO("Set the reset_gpio 0\n");
			gpio_direction_output(chip_info->hw_res->reset_gpio, 0);
		}

		tp_powercontrol_avdd(chip_info->hw_res, false);
		sec_mdelay(4);
		tp_powercontrol_vddi(chip_info->hw_res, false);

		chip_info->is_power_down = true;
	}

	return ret;
}

static fw_check_state sec_fw_check(void *chip_data,
		struct resolution_info *resolution_info, struct panel_info *panel_data)
{
	int ret = 0;
	int ver_len = 0;
	unsigned char data[5] = { 0 };
	char dev_version[MAX_DEVICE_VERSION_LENGTH] = {0};
	bool valid_fw_integrity = false;
	struct chip_data_s6sy791 *chip_info = (struct chip_data_s6sy791 *)chip_data;

	ret = touch_i2c_read_byte(chip_info->client,
			SEC_READ_FIRMWARE_INTEGRITY);  /*judge whether fw is right*/

	if (ret < 0) {
		TPD_INFO("%s: failed to do integrity check (%d)\n", __func__, ret);

	} else {
		if (ret & 0x80) {
			valid_fw_integrity = true;

		} else {
			valid_fw_integrity = false;
			TPD_INFO("invalid firmware integrity (%d)\n", ret);
		}
	}

	data[0] = touch_i2c_read_byte(chip_info->client, SEC_READ_BOOT_STATUS);
	ret = touch_i2c_read_block(chip_info->client, SEC_READ_TS_STATUS, 4, &data[1]);

	if (ret < 0) {
		TPD_INFO("%s: failed to read touch status\n", __func__);
	}

	if ((((data[0] == SEC_STATUS_APP_MODE) && (data[2] == TOUCH_SYSTEM_MODE_FLASH))
				|| (ret < 0)) && (valid_fw_integrity == false)) {
		TPD_INFO("%s: fw id abnormal, need update\n", __func__);
		return FW_ABNORMAL;
	}

	memset(data, 0, 5);
	touch_i2c_read_block(chip_info->client, SEC_READ_IMG_VERSION, 4, data);
	panel_data->tp_fw = (data[0] << 24) | (data[1] << 16) |
		(data[2] << 8) | data[3];

	if (panel_data->manufacture_info.version) {
		if (panel_data->vid_len == 0) {
			sprintf(panel_data->manufacture_info.version, "0x%x", panel_data->tp_fw);

		} else {
			ver_len = panel_data->vid_len;

			if (ver_len > MAX_DEVICE_VERSION_LENGTH - 4) {
				ver_len = MAX_DEVICE_VERSION_LENGTH - 4;
			}

			snprintf(dev_version, MAX_DEVICE_VERSION_LENGTH,
					"%X", panel_data->tp_fw);
			strlcpy(&panel_data->manufacture_info.version[ver_len],
					dev_version, MAX_DEVICE_VERSION_LENGTH - ver_len);
		}
	}

	/* ret = touch_i2c_write_block(chip_info->client, SEC_CMD_SENSE_ON, 0, NULL);*/
	/* TPD_INFO("%s: write sense on %s\n", (ret < 0) ? "failed" : "success");*/
	return FW_NORMAL;
}

static bool check_calibration(struct chip_data_s6sy791 *chip_info)
{
	u8 *data = NULL;
	int16_t temp_delta = 0, err_cnt = 0, judge_threshold = 2000;
	int ret = -1, x = 0, y = 0, z = 0;
	int readbytes = (chip_info->hw_res->tx_num * chip_info->hw_res->rx_num) * 2;

	data = tp_devm_kzalloc(&chip_info->client->dev, readbytes, GFP_KERNEL);

	if (!data) {
		return false;
	}

	ret = sec_read_mutual(chip_info, TYPE_AMBIENT_DATA, data, readbytes);

	if (ret < 0) {
		goto OUT;
	}

	for (x = 0; x < chip_info->hw_res->rx_num; x++) {
		for (y = chip_info->hw_res->tx_num - 1; y >= 0; y--) {
			z = chip_info->hw_res->tx_num * x + y;
			temp_delta = (data[z * 2] << 8) | data[z * 2 + 1];

			if (abs(temp_delta) > judge_threshold) {
				err_cnt++;
				TPD_INFO("node[%d][%d] = %d beyond %d\n", y, x, temp_delta, judge_threshold);
			}
		}
	}

OUT:

	if (data) {
		tp_devm_kfree(&chip_info->client->dev, (void **)&data, readbytes);
	}

	return err_cnt > 2;
}

static fw_update_state sec_fw_update(void *chip_data, const struct firmware *fw,
		bool force)
{
	int i = 0, ret = 0;
	u8 buf[4] = {0};
	u8 *fd = NULL;
	uint8_t cal_status = 0;
	sec_fw_chunk *fw_ch = NULL;
	sec_fw_header *fw_hd = NULL;
	fw_update_state update_state = FW_NO_NEED_UPDATE;
	uint32_t fw_version_in_bin = 0, fw_version_in_ic = 0;
	uint32_t config_version_in_bin = 0, config_version_in_ic = 0;
	struct chip_data_s6sy791 *chip_info = (struct chip_data_s6sy791 *)chip_data;
	struct monitor_data *monitor_data = chip_info->monitor_data;

	if (!chip_info) {
		TPD_INFO("Chip info is NULL\n");
		return 0;
	}

	TPD_INFO("%s is called, force update:%d\n", __func__, force);

	fd = (u8 *)(fw->data);
	fw_hd = (sec_fw_header *)(fw->data);
	buf[3] = (fw_hd->img_ver >> 24) & 0xff;
	buf[2] = (fw_hd->img_ver >> 16) & 0xff;
	buf[1] = (fw_hd->img_ver >> 8) & 0xff;
	buf[0] = (fw_hd->img_ver >> 0) & 0xff;
	fw_version_in_bin = (buf[0] << 24) | (buf[1] << 16) | (buf[2] << 8) | buf[3];
	memset(buf, 0, 4);
	touch_i2c_read_block(chip_info->client, SEC_READ_IMG_VERSION, 4, buf);
	fw_version_in_ic = (buf[0] << 24) | (buf[1] << 16) | (buf[2] << 8) | buf[3];
	TPD_INFO("img version in bin is 0x%04x, img version in ic is 0x%04x\n",
			fw_version_in_bin, fw_version_in_ic);

	buf[3] = (fw_hd->para_ver >> 24) & 0xff;
	buf[2] = (fw_hd->para_ver >> 16) & 0xff;
	buf[1] = (fw_hd->para_ver >> 8) & 0xff;
	buf[0] = (fw_hd->para_ver >> 0) & 0xff;
	config_version_in_bin = (buf[0] << 24) | (buf[1] << 16) |
		(buf[2] << 8) | buf[3];
	memset(buf, 0, 4);
	touch_i2c_read_block(chip_info->client, SEC_READ_CONFIG_VERSION, 4, buf);
	config_version_in_ic = (buf[0] << 24) | (buf[1] << 16) | (buf[2] << 8) | buf[3];
	TPD_INFO("config version in bin is 0x%04x, config version in ic is 0x%04x\n",
			config_version_in_bin, config_version_in_ic);

	ret = touch_i2c_read_byte(chip_info->client, SEC_READ_BOOT_STATUS);

	if (ret == SEC_STATUS_BOOT_MODE) {
		force = 1;
		TPD_INFO("%s: still in bootloader mode, will do force update\n", __func__);
	}

	if (!force) {
		if (fw_version_in_bin == fw_version_in_ic) {
			update_state = FW_NO_NEED_UPDATE;
			goto CAL_CHECK;
		}
	}

	if (sec_enter_fw_mode(chip_info)) {
		tp_healthinfo_report(monitor_data, HEALTH_FW_UPDATE, "Enter fw mode failed");
		TPD_INFO("%s: enter fw mode failed\n", __func__);
		update_state = FW_UPDATE_ERROR;
		goto CAL_CHECK;
	}

	if (fw_hd->signature != SEC_FW_HEADER_SIGN) {
		tp_healthinfo_report(monitor_data, HEALTH_FW_UPDATE, "Firmware header error");
		TPD_INFO("%s: firmware header error(0x%08x)\n", __func__, fw_hd->signature);
		update_state = FW_UPDATE_ERROR;
		goto CAL_CHECK;
	}

	fd += sizeof(sec_fw_header);

	for (i = 0; i < fw_hd->num_chunk; i++) {
		fw_ch = (sec_fw_chunk *)fd;
		TPD_INFO("update %d chunk(addr: 0x%08x, size: 0x%08x)\n", i, fw_ch->addr,
				fw_ch->size);

		if (fw_ch->signature != SEC_FW_CHUNK_SIGN) {
			tp_healthinfo_report(monitor_data, HEALTH_FW_UPDATE,
					"Firmware chunk signature error");
			TPD_INFO("%s: firmware chunk error(0x%08x)\n", __func__, fw_ch->signature);
			update_state = FW_UPDATE_ERROR;
			goto CAL_CHECK;
		}

		fd += sizeof(sec_fw_chunk);
		ret = sec_chunk_update(chip_info, fw_ch->addr, fw_ch->size, fd);

		if (ret < 0) {
			tp_healthinfo_report(monitor_data, HEALTH_FW_UPDATE, "Update chunk failed");
			TPD_INFO("update chunk failed\n");
			update_state = FW_UPDATE_ERROR;
			goto CAL_CHECK;
		}

		fd += fw_ch->size;
	}

	tp_healthinfo_report(monitor_data, HEALTH_FW_UPDATE, "FW Update Success");
	update_state = FW_UPDATE_SUCCESS;

	sec_reset(chip_info);
	cal_status = sec_read_calibration_report(
			chip_info);    /*read out calibration result*/

	if ((cal_status == 0) || (cal_status == 0xFF)
			|| (config_version_in_ic != config_version_in_bin)) {
		TPD_INFO("start calibration because of cal_status or config version changed\n");
		sec_execute_force_calibration(chip_info);
	}

CAL_CHECK:

	if (check_calibration(
				chip_info)) {                     /*check whether we need do calibration*/
		TPD_INFO("touchpanel have something wrong, need do calibration\n");
		chip_info->cal_needed =
			true;                       /*set flag to show touchpanel need to be calibrated*/
		sec_execute_force_calibration(chip_info);           /*do force calibration*/

		if (check_calibration(chip_info)) {
			TPD_INFO("set calibration flag to false\n");
			chip_info->cal_needed =
				false;                  /*set false when still check failed after calibration*/
		}
	}

	TPD_INFO("update firmware state: %s\n",
			(update_state == FW_UPDATE_SUCCESS) ? "update success!" : \
			(update_state == FW_UPDATE_ERROR) ? "update failed!" : "no need update!");
	return update_state;
}

static u32 sec_trigger_reason(void *chip_data, int gesture_enable,
		int is_suspended)
{
	int ret = 0;
	int event_id = 0;
	u8 left_event_cnt = 0;
	struct sec_event_status *p_event_status = NULL;
	struct chip_data_s6sy791 *chip_info = (struct chip_data_s6sy791 *)chip_data;

	if (chip_info->is_power_down) {
		TPD_DETAIL("%s: power down, just return\n", __func__);
		return IRQ_IGNORE;
	}

	memset(chip_info->first_event, 0, SEC_EVENT_BUFF_SIZE);
	ret = touch_i2c_read_block(chip_info->client, SEC_READ_ONE_EVENT,
			SEC_EVENT_BUFF_SIZE, chip_info->first_event);

	if (ret < 0) {
		TPD_DETAIL("%s: read one event failed\n", __func__);
		return IRQ_IGNORE;
	}

	TPD_DEBUG("first event: 0x%02x, 0x%02x, 0x%02x, 0x%02x, 0x%02x, 0x%02x, 0x%02x, 0x%02x\n",
			\
			chip_info->first_event[0], chip_info->first_event[1], chip_info->first_event[2],
			chip_info->first_event[3], \
			chip_info->first_event[4], chip_info->first_event[5], chip_info->first_event[6],
			chip_info->first_event[7]);

	if (chip_info->first_event[0] == 0) {
		TPD_DETAIL("%s: event buffer is empty\n", __func__);
		return IRQ_IGNORE;
	}

	left_event_cnt = chip_info->first_event[7] & 0x3F;

	if (left_event_cnt > MAX_EVENT_COUNT - 1) {
		TPD_INFO("%s: event buffer overflow, do clear the buffer\n", __func__);
		ret = touch_i2c_write_block(chip_info->client, SEC_CMD_CLEAR_EVENT_STACK, 0,
				NULL);

		if (ret < 0) {
			TPD_INFO("%s: clear event buffer failed\n", __func__);
		}

		return IRQ_IGNORE;
	}

	event_id = chip_info->first_event[0] & 0x3;

	if (event_id == SEC_STATUS_EVENT) {
		/* watchdog reset -> send SENSEON command */
		p_event_status = (struct sec_event_status *)chip_info->first_event;

		if ((p_event_status->stype == TYPE_STATUS_EVENT_INFO) &&
				(p_event_status->status_id == SEC_ACK_BOOT_COMPLETE)
				&& (p_event_status->status_data_1 == 0x20)) {
			ret = touch_i2c_write_block(chip_info->client, SEC_CMD_SENSE_ON, 0, NULL);

			if (ret < 0) {
				TPD_INFO("%s: write sense on failed\n", __func__);
			}

			return IRQ_FW_AUTO_RESET;
		}

		if ((p_event_status->stype == TYPE_STATUS_EVENT_INFO)
				&& (p_event_status->status_id == SEC_ACK_WET_MODE)) {
			TPD_INFO("wet mode status :%d\n", p_event_status->status_data_1);
		}

		if ((p_event_status->stype == TYPE_STATUS_EVENT_VENDOR_INFO)
				&& (p_event_status->status_id == SEC_VENDOR_INFO_NOISE_MODE)) {
			TPD_INFO("noise mode status :%d\n", p_event_status->status_data_1);
		}

		if ((p_event_status->stype == TYPE_STATUS_EVENT_VENDOR_INFO)
				&& (p_event_status->status_id == SEC_VENDOR_INFO_NOISE_LEVEL_CHANGED)) {
			TPD_INFO("noise mode level :%d\n", p_event_status->status_data_1);
		}

		if ((p_event_status->stype == TYPE_STATUS_EVENT_VENDOR_INFO)
				&& (p_event_status->status_id == SEC_STATUS_TOUCHHOLD)) {
			if (p_event_status->status_data_1 == 0x01) {
				chip_info->fp_info.touch_state = FINGERPRINT_DOWN_DETECT;
				chip_info->fp_info.x = p_event_status->status_data_2;
				chip_info->fp_info.x |= (p_event_status->status_data_3 & 0xF0) << 4;
				chip_info->fp_info.y = (p_event_status->status_data_3 & 0x0F) << 8;
				chip_info->fp_info.y |= p_event_status->status_data_4;

			} else if (p_event_status->status_data_1 == 0x00) {
				chip_info->fp_info.touch_state = FINGERPRINT_UP_DETECT;
				chip_info->fp_info.x = p_event_status->status_data_2;
				chip_info->fp_info.x |= (p_event_status->status_data_3 & 0xF0) << 4;
				chip_info->fp_info.y = (p_event_status->status_data_3 & 0x0F) << 8;
				chip_info->fp_info.y |= p_event_status->status_data_4;
			}

			return IRQ_FINGERPRINT;
		}

		/* event queue full-> all finger release */
		if ((p_event_status->stype == TYPE_STATUS_EVENT_ERR)
				&& (p_event_status->status_id == SEC_ERR_EVENT_QUEUE_FULL)) {
			TPD_INFO("%s: IC Event Queue is full\n", __func__);
			tp_touch_btnkey_release(chip_info->tp_index);
		}

		if ((p_event_status->stype == TYPE_STATUS_EVENT_ERR)
				&& (p_event_status->status_id == SEC_ERR_EVENT_ESD)) {
			TPD_INFO("%s: ESD detected. run reset\n", __func__);
			return IRQ_EXCEPTION;
		}

		if ((p_event_status->stype == TYPE_STATUS_EVENT_VENDOR_INFO)
				&& (p_event_status->status_id == SEC_STATUS_EARDETECTED)) {
			TPD_INFO("%s: EAR detected. \n", __func__);
			return IRQ_IGNORE;
		}

	} else if (event_id == SEC_COORDINATE_EVENT) {
		return IRQ_TOUCH;

	} else if (event_id == SEC_GESTURE_EVENT) {
		return IRQ_GESTURE;
	}

	return IRQ_IGNORE;
}

static int sec_get_touch_points(void *chip_data, struct point_info *points,
		int max_num)
{
	int i = 0;
	int t_id = 0;
	int ret = -1;
	int left_event = 0;
	struct sec_event_coordinate *p_event_coord = NULL;
	uint32_t obj_attention = 0;
	u8 event_buff[MAX_EVENT_COUNT][SEC_EVENT_BUFF_SIZE] = { { 0 } };
	struct chip_data_s6sy791 *chip_info = (struct chip_data_s6sy791 *)chip_data;

	p_event_coord = (struct sec_event_coordinate *)chip_info->first_event;
	t_id = (p_event_coord->tid - 1);

	if ((t_id < max_num) && ((p_event_coord->tchsta == SEC_COORDINATE_ACTION_PRESS)
				|| (p_event_coord->tchsta == SEC_COORDINATE_ACTION_MOVE))) {
		points[t_id].x = (p_event_coord->x_11_4 << 4) | (p_event_coord->x_3_0);
		points[t_id].y = (p_event_coord->y_11_4 << 4) | (p_event_coord->y_3_0);
		points[t_id].z = p_event_coord->z & 0x3F;
		points[t_id].width_major = p_event_coord->major;
		points[t_id].touch_major = p_event_coord->major;
		points[t_id].status = 1;

		if (points[t_id].z == 0) {
			points[t_id].z = 1;
		}

		obj_attention = obj_attention | (1 << t_id);    /*set touch bit*/


#ifdef CONFIG_OPLUS_TP_APK

		if (chip_info->debug_gesture_sta && chip_info->in_gesture) {
			if (chip_info->geture_points_count < 1000 && t_id < 3) {
				chip_info->gesture_buf[chip_info->geture_points_count * 4] = t_id;
				chip_info->gesture_buf[chip_info->geture_points_count * 4 + 1] =
					chip_info->first_event[1];
				chip_info->gesture_buf[chip_info->geture_points_count * 4 + 2] =
					chip_info->first_event[2];
				chip_info->gesture_buf[chip_info->geture_points_count * 4 + 3] =
					chip_info->first_event[3];
				chip_info->geture_points_count++;
			}
		}

#endif /* end of CONFIG_OPLUS_TP_APK*/
	}

	left_event = chip_info->first_event[7] & 0x3F;

	if (left_event == 0) {
		return obj_attention;

	} else if (left_event > max_num - 1) {
		TPD_INFO("%s: read left event beyond max touch points\n", __func__);
		left_event = max_num - 1;
	}

	ret = touch_i2c_read_block(chip_info->client, SEC_READ_ALL_EVENT,
			sizeof(u8) * (SEC_EVENT_BUFF_SIZE) * (left_event), (u8 *)event_buff[0]);

	if (ret < 0) {
		TPD_INFO("%s: i2c read all event failed\n", __func__);
		return obj_attention;
	}

	for (i = 0; i < left_event; i++) {
		p_event_coord = (struct sec_event_coordinate *)event_buff[i];
		t_id = (p_event_coord->tid - 1);

		if ((t_id < max_num) && ((p_event_coord->tchsta == SEC_COORDINATE_ACTION_PRESS)
					|| (p_event_coord->tchsta == SEC_COORDINATE_ACTION_MOVE))) {
			points[t_id].x = (p_event_coord->x_11_4 << 4) | (p_event_coord->x_3_0);
			points[t_id].y = (p_event_coord->y_11_4 << 4) | (p_event_coord->y_3_0);
			points[t_id].z = p_event_coord->z & 0x3F;
			points[t_id].width_major = p_event_coord->major;
			points[t_id].touch_major = p_event_coord->major;
			points[t_id].status = 1;

			if (points[t_id].z == 0) {
				points[t_id].z = 1;
			}

			obj_attention = obj_attention | (1 << t_id);    /*set touch bit*/

#ifdef CONFIG_OPLUS_TP_APK

			if (chip_info->debug_gesture_sta && chip_info->in_gesture) {
				if (chip_info->geture_points_count < 1000 && t_id < 3) {
					chip_info->gesture_buf[chip_info->geture_points_count * 4] = t_id;
					chip_info->gesture_buf[chip_info->geture_points_count * 4 + 1] =
						event_buff[i][1];
					chip_info->gesture_buf[chip_info->geture_points_count * 4 + 2] =
						event_buff[i][2];
					chip_info->gesture_buf[chip_info->geture_points_count * 4 + 3] =
						event_buff[i][3];
					chip_info->geture_points_count++;
				}
			}

#endif /* end of CONFIG_OPLUS_TP_APK*/
		}
	}

	return obj_attention;
}

#ifdef CONFIG_TOUCHPANEL_ALGORITHM
/* only do finger one*/
static int sec_get_touch_points_specail(void *chip_data,
		struct point_info *points, int max_num)
{
	int t_id = 0;
	struct sec_event_coordinate *p_event_coord = NULL;
	uint32_t obj_attention = 0;
	struct chip_data_s6sy791 *chip_info = (struct chip_data_s6sy791 *)chip_data;
	u8 t_type;

	p_event_coord = (struct sec_event_coordinate *)chip_info->first_event;
	t_id = (p_event_coord->tid - 1);

	if ((t_id < max_num)
			&& (p_event_coord->tchsta == SEC_COORDINATE_ACTION_RELEASE)) {
		t_type = p_event_coord->ttype_3_2 * 4 + p_event_coord->ttype_1_0;

		if (t_type == TYPE_SPECIAL_RELEASE) {
			points[t_id].x = (p_event_coord->x_11_4 << 4) | (p_event_coord->x_3_0);
			points[t_id].y = (p_event_coord->y_11_4 << 4) | (p_event_coord->y_3_0);
			points[t_id].z = p_event_coord->z & 0x3F;
			points[t_id].width_major = p_event_coord->major;
			points[t_id].touch_major = p_event_coord->major;
			points[t_id].status = 1;

			if (points[t_id].z == 0) {
				points[t_id].z = 1;
			}

			obj_attention = obj_attention | (1 << t_id);    /*set touch bit*/
		}
	}

	return obj_attention;
}
#endif


static int sec_get_gesture_info(void *chip_data, struct gesture_info *gesture)
{
	int i = 0, ret = -1;
	uint8_t coord[18] = {0};
	struct Coordinate limitPoint[4];
	struct sec_gesture_status *p_event_gesture = NULL;
	struct chip_data_s6sy791 *chip_info = (struct chip_data_s6sy791 *)chip_data;

	p_event_gesture = (struct sec_gesture_status *)chip_info->first_event;

	if (p_event_gesture->coordLen > 18) {
		p_event_gesture->coordLen = 18;
	}

	if (p_event_gesture->gestureId == GESTURE_EARSENSE) {
		TPD_DETAIL("earsense gesture: away from panel\n");
		return 0;
	}

	ret = touch_i2c_read_block(chip_info->client, SEC_READ_GESTURE_EVENT,
			p_event_gesture->coordLen, coord);

	if (ret < 0) {
		TPD_INFO("%s: read gesture data failed\n", __func__);
	}

	if (LEVEL_BASIC != tp_debug) {
		TPD_INFO("gesture points:");

		for (i = 0; i < p_event_gesture->coordLen / 3; i++) {
			printk("(%d, %d) ", (coord[3 * i] << 4) | ((coord[3 * i + 2] >> 0) & 0x0F),
					(coord[3 * i + 1] << 4) | ((coord[3 * i + 2] >> 4) & 0x0F));
		}
	}

	switch (p_event_gesture->gestureId) {   /*judge gesture type*/
		case GESTURE_RIGHT:
			gesture->gesture_type  = LEFT2RIGHT_SWIP;
			gesture->Point_start.x = (coord[0] << 4) | ((coord[2] >> 4) & 0x0F);
			gesture->Point_start.y = (coord[1] << 4) | ((coord[2] >> 0) & 0x0F);
			gesture->Point_end.x   = (coord[3] << 4) | ((coord[5] >> 4) & 0x0F);
			gesture->Point_end.y   = (coord[4] << 4) | ((coord[5] >> 0) & 0x0F);
			break;

		case GESTURE_LEFT:
			gesture->gesture_type  = RIGHT2LEFT_SWIP;
			gesture->Point_start.x = (coord[0] << 4) | ((coord[2] >> 4) & 0x0F);
			gesture->Point_start.y = (coord[1] << 4) | ((coord[2] >> 0) & 0x0F);
			gesture->Point_end.x   = (coord[3] << 4) | ((coord[5] >> 4) & 0x0F);
			gesture->Point_end.y   = (coord[4] << 4) | ((coord[5] >> 0) & 0x0F);
			break;

		case GESTURE_DOWN:
			gesture->gesture_type  = UP2DOWN_SWIP;
			gesture->Point_start.x = (coord[0] << 4) | ((coord[2] >> 4) & 0x0F);
			gesture->Point_start.y = (coord[1] << 4) | ((coord[2] >> 0) & 0x0F);
			gesture->Point_end.x   = (coord[3] << 4) | ((coord[5] >> 4) & 0x0F);
			gesture->Point_end.y   = (coord[4] << 4) | ((coord[5] >> 0) & 0x0F);
			break;

		case GESTURE_UP:
			gesture->gesture_type  = DOWN2UP_SWIP;
			gesture->Point_start.x = (coord[0] << 4) | ((coord[2] >> 4) & 0x0F);
			gesture->Point_start.y = (coord[1] << 4) | ((coord[2] >> 0) & 0x0F);
			gesture->Point_end.x   = (coord[3] << 4) | ((coord[5] >> 4) & 0x0F);
			gesture->Point_end.y   = (coord[4] << 4) | ((coord[5] >> 0) & 0x0F);
			break;

		case GESTURE_DOUBLECLICK:
			gesture->gesture_type  = DOU_TAP;
			gesture->Point_start.x = (coord[0] << 4) | ((coord[2] >> 4) & 0x0F);
			gesture->Point_start.y = (coord[1] << 4) | ((coord[2] >> 0) & 0x0F);
			gesture->Point_end     = gesture->Point_start;
			break;

		case GESTURE_UP_V:
			gesture->gesture_type  = UP_VEE;
			gesture->Point_start.x = (coord[0] << 4) | ((coord[2] >> 4) & 0x0F);
			gesture->Point_start.y = (coord[1] << 4) | ((coord[2] >> 0) & 0x0F);
			gesture->Point_end.x   = (coord[6] << 4) | ((coord[8] >> 4) & 0x0F);
			gesture->Point_end.y   = (coord[7] << 4) | ((coord[8] >> 0) & 0x0F);
			gesture->Point_1st.x   = (coord[3] << 4) | ((coord[5] >> 4) & 0x0F);
			gesture->Point_1st.y   = (coord[4] << 4) | ((coord[5] >> 0) & 0x0F);
			break;

		case GESTURE_DOWN_V:
			gesture->gesture_type  = DOWN_VEE;
			gesture->Point_start.x = (coord[0] << 4) | ((coord[2] >> 4) & 0x0F);
			gesture->Point_start.y = (coord[1] << 4) | ((coord[2] >> 0) & 0x0F);
			gesture->Point_end.x   = (coord[6] << 4) | ((coord[8] >> 4) & 0x0F);
			gesture->Point_end.y   = (coord[7] << 4) | ((coord[8] >> 0) & 0x0F);
			gesture->Point_1st.x   = (coord[3] << 4) | ((coord[5] >> 4) & 0x0F);
			gesture->Point_1st.y   = (coord[4] << 4) | ((coord[5] >> 0) & 0x0F);
			break;

		case GESTURE_LEFT_V:
			gesture->gesture_type = LEFT_VEE;
			gesture->Point_start.x = (coord[0] << 4) | ((coord[2] >> 4) & 0x0F);
			gesture->Point_start.y = (coord[1] << 4) | ((coord[2] >> 0) & 0x0F);
			gesture->Point_end.x   = (coord[6] << 4) | ((coord[8] >> 4) & 0x0F);
			gesture->Point_end.y   = (coord[7] << 4) | ((coord[8] >> 0) & 0x0F);
			gesture->Point_1st.x   = (coord[3] << 4) | ((coord[5] >> 4) & 0x0F);
			gesture->Point_1st.y   = (coord[4] << 4) | ((coord[5] >> 0) & 0x0F);
			break;

		case GESTURE_RIGHT_V:
			gesture->gesture_type  = RIGHT_VEE;
			gesture->Point_start.x = (coord[0] << 4) | ((coord[2] >> 4) & 0x0F);
			gesture->Point_start.y = (coord[1] << 4) | ((coord[2] >> 0) & 0x0F);
			gesture->Point_end.x   = (coord[6] << 4) | ((coord[8] >> 4) & 0x0F);
			gesture->Point_end.y   = (coord[7] << 4) | ((coord[8] >> 0) & 0x0F);
			gesture->Point_1st.x   = (coord[3] << 4) | ((coord[5] >> 4) & 0x0F);
			gesture->Point_1st.y   = (coord[4] << 4) | ((coord[5] >> 0) & 0x0F);
			break;

		case GESTURE_O:
			gesture->gesture_type = CIRCLE_GESTURE;
			gesture->clockwise = (p_event_gesture->data == 0) ? 1 : 0;
			gesture->Point_start.x = (coord[0] << 4) | ((coord[2] >> 4) & 0x0F);
			gesture->Point_start.y = (coord[1] << 4) | ((coord[2] >> 0) & 0x0F);
			limitPoint[0].x   = (coord[3] << 4) | ((coord[5] >> 4) & 0x0F);    /*ymin*/
			limitPoint[0].y   = (coord[4] << 4) | ((coord[5] >> 0) & 0x0F);
			limitPoint[1].x   = (coord[6] << 4) | ((coord[8] >> 4) & 0x0F);    /*xmin*/
			limitPoint[1].y   = (coord[7] << 4) | ((coord[8] >> 0) & 0x0F);
			limitPoint[2].x   = (coord[9] << 4) | ((coord[11] >> 4) & 0x0F);   /*ymax*/
			limitPoint[2].y   = (coord[10] << 4) | ((coord[11] >> 0) & 0x0F);
			limitPoint[3].x   = (coord[12] << 4) | ((coord[14] >> 4) & 0x0F);  /*xmax*/
			limitPoint[3].y   = (coord[13] << 4) | ((coord[14] >> 0) & 0x0F);
			gesture->Point_end.x   = (coord[15] << 4) | ((coord[17] >> 4) & 0x0F);
			gesture->Point_end.y   = (coord[16] << 4) | ((coord[17] >> 0) & 0x0F);
			handleFourCornerPoint(&limitPoint[0], 4);
			gesture->Point_1st = limitPoint[0]; /*ymin*/
			gesture->Point_2nd = limitPoint[1]; /*xmin*/
			gesture->Point_3rd = limitPoint[2]; /*ymax*/
			gesture->Point_4th = limitPoint[3]; /*xmax*/
			break;

		case GESTURE_DOUBLE_LINE:
			gesture->gesture_type  = DOU_SWIP;
			gesture->Point_start.x = (coord[0] << 4) | ((coord[2] >> 4) & 0x0F);
			gesture->Point_start.y = (coord[1] << 4) | ((coord[2] >> 0) & 0x0F);
			gesture->Point_end.x   = (coord[3] << 4) | ((coord[5] >> 4) & 0x0F);
			gesture->Point_end.y   = (coord[4] << 4) | ((coord[5] >> 0) & 0x0F);
			gesture->Point_1st.x   = (coord[6] << 4) | ((coord[8] >> 4) & 0x0F);
			gesture->Point_1st.y   = (coord[7] << 4) | ((coord[8] >> 0) & 0x0F);
			gesture->Point_2nd.x   = (coord[9] << 4) | ((coord[11] >> 4) & 0x0F);
			gesture->Point_2nd.y   = (coord[10] << 4) | ((coord[11] >> 0) & 0x0F);
			break;

		case GESTURE_M:
			gesture->gesture_type  = M_GESTRUE;
			gesture->Point_start.x = (coord[0] << 4) | ((coord[2] >> 4) & 0x0F);
			gesture->Point_start.y = (coord[1] << 4) | ((coord[2] >> 0) & 0x0F);
			gesture->Point_1st.x   = (coord[3] << 4) | ((coord[5] >> 4) & 0x0F);
			gesture->Point_1st.y   = (coord[4] << 4) | ((coord[5] >> 0) & 0x0F);
			gesture->Point_2nd.x   = (coord[6] << 4) | ((coord[8] >> 4) & 0x0F);
			gesture->Point_2nd.y   = (coord[7] << 4) | ((coord[8] >> 0) & 0x0F);
			gesture->Point_3rd.x   = (coord[9] << 4) | ((coord[11] >> 4) & 0x0F);
			gesture->Point_3rd.y   = (coord[10] << 4) | ((coord[11] >> 0) & 0x0F);
			gesture->Point_end.x   = (coord[12] << 4) | ((coord[14] >> 4) & 0x0F);
			gesture->Point_end.y   = (coord[13] << 4) | ((coord[14] >> 0) & 0x0F);
			break;

		case GESTURE_W:
			gesture->gesture_type  = W_GESTURE;
			gesture->Point_start.x = (coord[0] << 4) | ((coord[2] >> 4) & 0x0F);
			gesture->Point_start.y = (coord[1] << 4) | ((coord[2] >> 0) & 0x0F);
			gesture->Point_1st.x   = (coord[3] << 4) | ((coord[5] >> 4) & 0x0F);
			gesture->Point_1st.y   = (coord[4] << 4) | ((coord[5] >> 0) & 0x0F);
			gesture->Point_2nd.x   = (coord[6] << 4) | ((coord[8] >> 4) & 0x0F);
			gesture->Point_2nd.y   = (coord[7] << 4) | ((coord[8] >> 0) & 0x0F);
			gesture->Point_3rd.x   = (coord[9] << 4) | ((coord[11] >> 4) & 0x0F);
			gesture->Point_3rd.y   = (coord[10] << 4) | ((coord[11] >> 0) & 0x0F);
			gesture->Point_end.x   = (coord[12] << 4) | ((coord[14] >> 4) & 0x0F);
			gesture->Point_end.y   = (coord[13] << 4) | ((coord[14] >> 0) & 0x0F);
			break;

		default:
			gesture->gesture_type = UNKOWN_GESTURE;
			break;
	}

#ifdef CONFIG_OPLUS_TP_APK
	chip_info->debug_gesture_type = gesture->gesture_type;
#endif
	TPD_INFO("%s, gesture_id: 0x%x, gesture_type: %d, clockwise: %d, points: (%d, %d)(%d, %d)(%d, %d)(%d, %d)(%d, %d)(%d, %d)\n",
			\
			__func__, p_event_gesture->gestureId, gesture->gesture_type, gesture->clockwise,
			\
			gesture->Point_start.x, gesture->Point_start.y, \
			gesture->Point_end.x, gesture->Point_end.y, \
			gesture->Point_1st.x, gesture->Point_1st.y, \
			gesture->Point_2nd.x, gesture->Point_2nd.y, \
			gesture->Point_3rd.x, gesture->Point_3rd.y, \
			gesture->Point_4th.x, gesture->Point_4th.y);

	return 0;
}

static void sec_change_to_np_mode(void *chip_data)
{
	int ret = -1;
	int i = 0;
	struct chip_data_s6sy791 *chip_info = (struct chip_data_s6sy791 *)chip_data;

	if (!*chip_info->in_suspend) {
		for (i = 0; i < 20; i++) {
			ret = touch_i2c_read_byte(chip_info->client, SEC_CMD_SET_POWER_MODE);

			if (0x00 == ret) {
				break;
			}

			touch_i2c_write_byte(chip_info->client, SEC_CMD_SET_POWER_MODE, 0x00);
			sec_mdelay(10);
		}

		TPD_INFO("%s: change to np_mode time: %d %s!\n", __func__, i,
				ret < 0 ? "failed" : "success");
	}
}

static void sec_enable_fingerprint_mode(void *chip_data, uint32_t enable)
{
	int ret = -1;
	int i = 0;
	struct chip_data_s6sy791 *chip_info = (struct chip_data_s6sy791 *)chip_data;

	if (chip_info->is_power_down) {
		sec_power_control(chip_info, true);
	}

	if (enable == 1) {
		for (i = 0; i < 10; i++) {
			ret = touch_i2c_read_byte(chip_info->client, SEC_CMD_TOUCHHOLD_SWITCH);
			ret |= 0x01;
			ret = touch_i2c_write_byte(chip_info->client, SEC_CMD_TOUCHHOLD_SWITCH, ret);
			sec_mdelay(10);
			ret = touch_i2c_read_byte(chip_info->client, SEC_CMD_TOUCHHOLD_SWITCH);

			if (ret == 1) {
				break;
			}
		}

	} else if (enable == 0) {
		ret = touch_i2c_read_byte(chip_info->client, SEC_CMD_TOUCHHOLD_SWITCH);
		ret &= 0xFE;
		ret = touch_i2c_write_byte(chip_info->client, SEC_CMD_TOUCHHOLD_SWITCH, ret);
		sec_change_to_np_mode(chip_data);

		chip_info->fp_info.touch_state = 0;
	}

	TPD_INFO("%s: touchhold_enable: %d %s!\n", __func__, enable,
			ret < 0 ? "failed" : "success");
	return;
}

static void sec_get_fingerprint_info(void *chip_data,
		struct fp_underscreen_info *fp_tpinfo)
{
	struct chip_data_s6sy791 *chip_info = (struct chip_data_s6sy791 *)chip_data;

	fp_tpinfo->touch_state = chip_info->fp_info.touch_state;
	fp_tpinfo->x = chip_info->fp_info.x;
	fp_tpinfo->y = chip_info->fp_info.y;

	if (chip_info->fp_info.touch_state == FINGERPRINT_UP_DETECT) {
		sec_change_to_np_mode(chip_data);
	}
}

static int sec_mode_switch(void *chip_data, work_mode mode, int flag)
{
	int ret = -1;
	struct chip_data_s6sy791 *chip_info = (struct chip_data_s6sy791 *)chip_data;

	if (chip_info->is_power_down) {
		sec_power_control(chip_info, true);
	}

	switch (mode) {
		case MODE_NORMAL:
			ret = 0;
			break;

		case MODE_SLEEP:
			ret = sec_power_control(chip_info, false);

			if (ret < 0) {
				TPD_INFO("%s: power down failed\n", __func__);
			}

			break;

		case MODE_GESTURE:
			ret = sec_enable_black_gesture(chip_info, flag);

			if (ret < 0) {
				TPD_INFO("%s: sec enable gesture failed.\n", __func__);
				return ret;
			}

			break;

		case MODE_EDGE:
			/*ret = sec_enable_edge_limit(chip_info, flag);*/
			/*if (ret < 0) {*/
			/*    TPD_INFO("%s: sec enable edg limit failed.\n", __func__);*/
			/*    return ret;*/
			/*}*/
			break;

		case MODE_CHARGE:
			ret = sec_enable_charge_mode(chip_info, flag);

			if (ret < 0) {
				TPD_INFO("%s: enable charge mode : %d failed\n", __func__, flag);
			}

			break;

		case MODE_PALM_REJECTION:
			ret = sec_enable_palm_reject(chip_info, flag);

			if (ret < 0) {
				TPD_INFO("%s: enable palm rejection: %d failed\n", __func__, flag);
			}

			break;

		case MODE_GAME:
			ret = sec_enable_game_mode(chip_info, flag);

			if (ret < 0) {
				TPD_INFO("%s: enable game mode: %d failed\n", __func__, flag);
			}

			break;

		case MODE_HEADSET:
			ret = sec_enable_headset_mode(chip_info, flag);

			if (ret < 0) {
				TPD_INFO("%s: enable headset mode: %d failed\n", __func__, flag);
			}

			break;

		default:
			TPD_INFO("%s: Wrong mode.\n", __func__);
	}

	return ret;
}

static void sec_set_touch_direction(void *chip_data, uint8_t dir)
{
	struct chip_data_s6sy791 *chip_info = (struct chip_data_s6sy791 *)chip_data;

	chip_info->touch_direction = dir;
}

static uint8_t sec_get_touch_direction(void *chip_data)
{
	struct chip_data_s6sy791 *chip_info = (struct chip_data_s6sy791 *)chip_data;

	return chip_info->touch_direction;
}

static void sec_enable_kernel_grip(void *chip_data,
		struct kernel_grip_info *grip_info)
{
	struct list_head *pos = NULL;
	struct grip_zone_area *grip_zone = NULL;
	struct chip_data_s6sy791 *chip_info = (struct chip_data_s6sy791 *)chip_data;
	int i = 0;

	if (!grip_info || !grip_info->grip_handle_in_fw) {
		return;
	}

	list_for_each(pos, &grip_info->large_zone_list) {
		grip_zone = (struct grip_zone_area *)pos;

		for (i = 0; i < ARRAY_SIZE(sec_grip); i++) {
			if (!strncmp(grip_zone->name, sec_grip[i].name, GRIP_TAG_SIZE)) {
				if (sec_grip[i].handle_func) {
					sec_grip[i].handle_func(chip_info, grip_zone, true);
				}
			}
		}
	}

	list_for_each(pos, &grip_info->dead_zone_list) {
		grip_zone = (struct grip_zone_area *)pos;

		for (i = 0; i < ARRAY_SIZE(sec_grip); i++) {
			if (!strncmp(grip_zone->name, sec_grip[i].name, GRIP_TAG_SIZE)) {
				if (sec_grip[i].handle_func) {
					sec_grip[i].handle_func(chip_info, grip_zone, true);
				}
			}
		}
	}

	list_for_each(pos, &grip_info->condition_zone_list) {
		grip_zone = (struct grip_zone_area *)pos;

		for (i = 0; i < ARRAY_SIZE(sec_grip); i++) {
			if (!strncmp(grip_zone->name, sec_grip[i].name, GRIP_TAG_SIZE)) {
				if (sec_grip[i].handle_func) {
					sec_grip[i].handle_func(chip_info, grip_zone, true);
				}
			}
		}
	}

	sec_set_no_handle_area(chip_data, grip_info);
	sec_set_condition_frame_limit(chip_data, grip_info->condition_frame_limit);
	sec_set_large_frame_limit(chip_data, grip_info->large_frame_limit);
	sec_set_large_corner_frame_limit(chip_data,
			grip_info->large_corner_frame_limit);
	sec_set_grip_touch_direction(chip_data, grip_info->touch_dir);
}

static void sec_rate_white_list_ctrl(void *chip_data, int value)
{
	struct chip_data_s6sy791 *chip_info = (struct chip_data_s6sy791 *)chip_data;

	if (value >= 0 && value < 255) {
		int ret = -1;
		ret = touch_i2c_write_byte(chip_info->client, SEC_CMD_GAME_MODE,
				(unsigned char)value);
		TPD_INFO("%s: state: %d %s!\n", __func__, value,
				ret < 0 ? "failed" : "success");
	}
}

static struct oplus_touchpanel_operations sec_ops = {
	.ftm_process                = sec_ftm_process,
	.get_vendor                 = sec_get_vendor,
	.get_chip_info              = sec_get_chip_info,
	.reset                      = sec_reset,
	.power_control              = sec_power_control,
	.fw_check                   = sec_fw_check,
	.fw_update                  = sec_fw_update,
	.trigger_reason         = sec_trigger_reason,
	.get_touch_points           = sec_get_touch_points,
	.get_gesture_info           = sec_get_gesture_info,
	.mode_switch                = sec_mode_switch,
	.set_touch_direction        = sec_set_touch_direction,
	.get_touch_direction        = sec_get_touch_direction,
	.enable_kernel_grip         = sec_enable_kernel_grip,
	.enable_fingerprint         = sec_enable_fingerprint_mode,
	.screenon_fingerprint_info  = sec_get_fingerprint_info,
	.enable_gesture_mask        = sec_enable_gesture_mask,
	.rate_white_list_ctrl       = sec_rate_white_list_ctrl,
#ifdef CONFIG_TOUCHPANEL_ALGORITHM
	.special_points_report      = sec_get_touch_points_specail,
#endif
};
/********* End of implementation of oplus_touchpanel_operations callbacks**********************/


/**************** Start of implementation of debug_info proc callbacks************************/
static int sec_fix_tmode(struct chip_data_s6sy791 *chip_info, u8 mode, u8 state)
{
	int ret = -1;
	u8 tBuff[2] = { mode, state };

	ret = touch_i2c_write_byte(chip_info->client, SEC_CMD_STATEMANAGE_ON,
			STATE_MANAGE_OFF);
	sec_mdelay(20);
	ret |= touch_i2c_write_block(chip_info->client, SEC_CMD_CHG_SYSMODE,
			sizeof(tBuff), tBuff);
	sec_mdelay(20);

	return ret;
}

static int sec_release_tmode(struct chip_data_s6sy791 *chip_info)
{
	int ret = -1;

	ret = touch_i2c_write_byte(chip_info->client, SEC_CMD_STATEMANAGE_ON,
			STATE_MANAGE_ON);
	sec_mdelay(20);

	return ret;
}

static int sec_read_self(struct chip_data_s6sy791 *chip_info, u8 type,
		char *data, int len)
{
	int ret = 0;
	unsigned int data_len = (chip_info->hw_res->tx_num + chip_info->hw_res->rx_num)
		* 2;

	if (len != data_len) {
		return -1;
	}

	ret = sec_fix_tmode(chip_info, TOUCH_SYSTEM_MODE_TOUCH, TOUCH_MODE_STATE_TOUCH);

	if (ret < 0) {
		TPD_INFO("%s: fix touch mode failed\n", __func__);
		goto err_out;
	}

	ret = touch_i2c_write_byte(chip_info->client, SEC_CMD_SELF_RAW_TYPE, type);

	if (ret < 0) {
		TPD_INFO("%s: Set self type failed\n", __func__);
		goto err_out;
	}

	sec_mdelay(50);
	ret = touch_i2c_read_block(chip_info->client, SEC_READ_TOUCH_SELF_RAWDATA,
			data_len, data);

	if (ret < 0) {
		TPD_INFO("%s: read self failed!\n", __func__);
	}

	/* release data monitory (unprepare AFE data memory) */
	ret |= touch_i2c_write_byte(chip_info->client, SEC_CMD_SELF_RAW_TYPE,
			TYPE_INVALID_DATA);

	if (ret < 0) {
		TPD_INFO("%s: Set self type failed\n", __func__);
	}

err_out:
	ret |= sec_release_tmode(chip_info);

	return ret;
}

static int sec_read_mutual(struct chip_data_s6sy791 *chip_info, u8 type,
		char *data, int len)
{
	int ret = 0;
	/*u8 buf[2] = {0};*/
	unsigned int data_len = (chip_info->hw_res->tx_num * chip_info->hw_res->rx_num)
		* 2;

	if ((len > data_len) || (len % chip_info->hw_res->tx_num != 0)) {
		return -1;
	}

	ret = sec_fix_tmode(chip_info, TOUCH_SYSTEM_MODE_TOUCH, TOUCH_MODE_STATE_TOUCH);

	if (ret < 0) {
		TPD_INFO("%s: fix touch mode failed\n", __func__);
		goto err_out;
	}

	ret = touch_i2c_write_byte(chip_info->client, SEC_CMD_MUTU_RAW_TYPE, type);

	if (ret < 0) {
		TPD_INFO("%s: Set mutual type failed\n", __func__);
		goto err_out;
	}

	sec_mdelay(20);
	/*buf[0] = (u8)((len >> 8) & 0xFF);*/
	/*buf[1] = (u8)(len & 0xFF);*/
	/*touch_i2c_write_block(chip_info->client, SEC_CMD_TOUCH_RAWDATA_SETLEN, 2, buf);*/
	ret = touch_i2c_read_block(chip_info->client, SEC_READ_TOUCH_RAWDATA, len,
			data);

	if (ret < 0) {
		TPD_INFO("%s: read mutual failed!\n", __func__);
	}

	/* release data monitory (unprepare AFE data memory) */
	ret = touch_i2c_write_byte(chip_info->client, SEC_CMD_MUTU_RAW_TYPE,
			TYPE_INVALID_DATA);

	if (ret < 0) {
		TPD_INFO("%s: Set mutual type failed\n", __func__);
	}

err_out:
	ret |= sec_release_tmode(chip_info);

	return ret;
}

static void sec_delta_read(struct seq_file *s, void *chip_data)
{
	u8 *data = NULL;
	int16_t x = 0, y = 0, z = 0, temp_delta = 0, ret = 0;
	struct chip_data_s6sy791 *chip_info = (struct chip_data_s6sy791 *)chip_data;
	int readbytes = chip_info->hw_res->tx_num * (chip_info->hw_res->rx_num) * 2;

	data = tp_devm_kzalloc(&chip_info->client->dev, readbytes, GFP_KERNEL);

	if (!data) {
		return;
	}

	ret = sec_read_mutual(chip_info, TYPE_SIGNAL_DATA, data, readbytes);

	if (ret < 0) {
		seq_printf(s, "read delta failed\n");
		goto kfree_out;
	}

	seq_printf(s, "SIGNAL DATA:");

	for (x = 0; x < chip_info->hw_res->tx_num; x++) {
		seq_printf(s, "\n[%2d]", x);

		for (y = chip_info->hw_res->rx_num - 1; y >= 0; y--) {
			z = chip_info->hw_res->rx_num * x + y;
			temp_delta = ((data[z * 2] << 8) | data[z * 2 + 1]);
			seq_printf(s, "%4d, ", temp_delta);
		}
	}

	seq_printf(s, "\n");

	/*read ambient data*/
	memset(data, 0, readbytes);
	ret = sec_read_mutual(chip_info, TYPE_AMBIENT_DATA, data, readbytes);

	if (ret < 0) {
		seq_printf(s, "read rawdata failed\n");
		goto kfree_out;
	}

	seq_printf(s, "AMBIENT DATA:");

	for (x = 0; x < chip_info->hw_res->tx_num; x++) {
		seq_printf(s, "\n[%2d]", x);

		for (y = chip_info->hw_res->rx_num - 1; y >= 0; y--) {
			z = chip_info->hw_res->rx_num * x + y;
			temp_delta = (data[z * 2] << 8) | data[z * 2 + 1];
			seq_printf(s, "%4d, ", temp_delta);
		}
	}

	seq_printf(s, "\n");

kfree_out:
	tp_devm_kfree(&chip_info->client->dev, (void **)&data, readbytes);
	return;
}

static void sec_baseline_read(struct seq_file *s, void *chip_data)
{
	u8 *data = NULL;
	int16_t x = 0, y = 0, z = 0, temp_delta = 0, ret = -1;
	struct chip_data_s6sy791 *chip_info = (struct chip_data_s6sy791 *)chip_data;
	int readbytes = (chip_info->hw_res->tx_num * chip_info->hw_res->rx_num) * 2;

	data = tp_devm_kzalloc(&chip_info->client->dev, readbytes, GFP_KERNEL);

	if (!data) {
		return;
	}

	/*read decoded data*/
	ret = sec_read_mutual(chip_info, TYPE_DECODED_DATA, data, readbytes);

	if (ret < 0) {
		seq_printf(s, "read rawdata failed\n");
		goto kfree_out;
	}

	seq_printf(s, "DECODED DATA:");

	for (x = 0; x < chip_info->hw_res->tx_num; x++) {
		seq_printf(s, "\n[%2d]", x);

		for (y = chip_info->hw_res->rx_num - 1; y >= 0; y--) {
			z = chip_info->hw_res->rx_num * x + y;
			temp_delta = (data[z * 2] << 8) | data[z * 2 + 1];
			seq_printf(s, "%4d, ", temp_delta);
		}
	}

	seq_printf(s, "\n");

kfree_out:
	tp_devm_kfree(&chip_info->client->dev, (void **)&data, readbytes);
	return;
}

static void sec_self_delta_read(struct seq_file *s, void *chip_data)
{
	u8 *data = NULL;
	int16_t x = 0, rx_offset = 0, temp_delta = 0, ret = -1;
	struct chip_data_s6sy791 *chip_info = (struct chip_data_s6sy791 *)chip_data;
	int readbytes = (chip_info->hw_res->tx_num + chip_info->hw_res->rx_num) * 2;

	data = tp_devm_kzalloc(&chip_info->client->dev, readbytes, GFP_KERNEL);

	if (!data) {
		return;
	}

	ret = sec_read_self(chip_info, TYPE_SIGNAL_DATA, data, readbytes);

	if (ret < 0) {
		seq_printf(s, "read self delta failed\n");
		goto kfree_out;
	}

	seq_printf(s, "TX:\n");

	for (x = 0; x < chip_info->hw_res->tx_num; x++) {
		temp_delta = (data[x * 2] << 8) | data[x * 2 + 1];
		seq_printf(s, "%4d, ", temp_delta);
	}

	seq_printf(s, "\nRX:\n");
	rx_offset = chip_info->hw_res->tx_num * 2;

	for (x = 0; x < chip_info->hw_res->rx_num; x++) {
		temp_delta = (data[x * 2 + rx_offset] << 8) | data[x * 2 + 1 + rx_offset];
		seq_printf(s, "%4d, ", temp_delta);
	}

	seq_printf(s, "\n");

kfree_out:
	tp_devm_kfree(&chip_info->client->dev, (void **)&data, readbytes);
	return;
}

static void sec_self_raw_read(struct seq_file *s, void *chip_data)
{
	u8 *data = NULL;
	int16_t x = 0, rx_offset = 0, temp_delta = 0, ret = -1;
	struct chip_data_s6sy791 *chip_info = (struct chip_data_s6sy791 *)chip_data;
	int readbytes = (chip_info->hw_res->tx_num + chip_info->hw_res->rx_num) * 2;

	data = tp_devm_kzalloc(&chip_info->client->dev, readbytes, GFP_KERNEL);

	if (!data) {
		return;
	}

	ret = sec_read_self(chip_info, TYPE_RAW_DATA, data, readbytes);

	if (ret < 0) {
		seq_printf(s, "read self rawdata failed\n");
		goto kfree_out;
	}

	seq_printf(s, "TX:\n");

	for (x = 0; x < chip_info->hw_res->tx_num; x++) {
		temp_delta = (data[x * 2] << 8) | data[x * 2 + 1];
		seq_printf(s, "%4d, ", temp_delta);
	}

	seq_printf(s, "\nRX:\n");
	rx_offset = chip_info->hw_res->tx_num * 2;

	for (x = 0; x < chip_info->hw_res->rx_num; x++) {
		temp_delta = (data[x * 2 + rx_offset] << 8) | data[x * 2 + 1 + rx_offset];
		seq_printf(s, "%4d, ", temp_delta);
	}

	seq_printf(s, "\n");

kfree_out:
	tp_devm_kfree(&chip_info->client->dev, (void **)&data, readbytes);
	return;
}

static void sec_main_register_read(struct seq_file *s, void *chip_data)
{
	u8 buf[4] = {0};
	u8 grip_buf[5] = {0};
	int state = -1;
	struct chip_data_s6sy791 *chip_info = (struct chip_data_s6sy791 *)chip_data;

	state = sec_read_calibration_report(chip_info);
	seq_printf(s, "calibration status: 0x%02x\n", state);

	state = sec_get_verify_result(chip_info);
	seq_printf(s, "calibration result: 0x%02x\n", state);

	state = touch_i2c_read_byte(chip_info->client, SET_CMD_SET_CHARGER_MODE);
	seq_printf(s, "charger state: 0x%02x\n", state);

	state = touch_i2c_read_byte(chip_info->client, SEC_CMD_NOISE_CTRL);
	seq_printf(s, "noise state: 0x%02x(0x10:normal/0x11:noise mode)\n", state);

	memset(buf, 0, 4);
	touch_i2c_read_block(chip_info->client, SEC_READ_ID, 3, buf);
	seq_printf(s, "boot state: 0x%02x\n", buf[0]);

	state = touch_i2c_read_byte(chip_info->client, 0x30);
	seq_printf(s,
			"touch function: 0x%02x(proximity/wetmode/palm/stylus/glove/cover/hover/touch)\n",
			state);

	state = touch_i2c_read_byte(chip_info->client, SEC_CMD_WET_SWITCH);
	seq_printf(s, "wetmode switch: 0x%02x\n", state);

	state = touch_i2c_read_byte(chip_info->client, 0x3B);
	seq_printf(s, "wetmode state: 0x%02x\n", state);

	state = touch_i2c_read_word(chip_info->client, SEC_CMD_WAKEUP_GESTURE_MODE);
	seq_printf(s, "gesture mode: 0x%04x\n", state);

	memset(buf, 0, 4);
	touch_i2c_read_block(chip_info->client, SEC_READ_IMG_VERSION, 4, buf);
	seq_printf(s, "fw img version: 0x%08x\n",
			(buf[0] << 24) | (buf[1] << 16) | (buf[2] << 8) | buf[3]);

	memset(buf, 0, 4);
	touch_i2c_read_block(chip_info->client, SEC_READ_CONFIG_VERSION, 4, buf);
	seq_printf(s, "config version: 0x%08x\n",
			(buf[0] << 24) | (buf[1] << 16) | (buf[2] << 8) | buf[3]);

	state = touch_i2c_read_byte(chip_info->client, SEC_CMD_STATEMANAGE_ON);
	seq_printf(s, "auto change enabled: 0x%02x\n", state);

	state = touch_i2c_read_word(chip_info->client, SEC_CMD_PALM_SWITCH);
	seq_printf(s, "palm state: 0x%04x(0x0041-off/0x0061-on)\n", state);

	memset(buf, 0, 4);
	touch_i2c_read_block(chip_info->client, SEC_READ_TS_STATUS, 4, buf);
	seq_printf(s,
			"power mode: 0x%02x[normal-0x02/lpwg-0x05], 0x%02x[indle-0x00/active-0x02]\n",
			buf[1], buf[3]);


	memset(grip_buf, 0, 5);
	touch_i2c_read_block(chip_info->client, SEC_CMD_GRIP_ENABLE, 1, grip_buf);
	seq_printf(s, "grip enable bit : 0x%02x\n", grip_buf[0]);

	memset(grip_buf, 0, 5);
	touch_i2c_read_block(chip_info->client, SEC_CMD_GRIP_DIRECTION, 1, grip_buf);
	seq_printf(s,
			"touch direction(0x00 (portrait mode), 0x01 (landscape mode), 0x02 (reverse landscape mode), 0x03 (reverse portrait mode)) : 0x%02x\n",
			grip_buf[0]);

	memset(grip_buf, 0, 5);
	touch_i2c_write_byte(chip_info->client, SEC_CMD_GRIP_AREA, DEAD_ZONE_TYPE_1);
	touch_i2c_read_block(chip_info->client, SEC_CMD_GRIP_AREA, 5, grip_buf);
	seq_printf(s, "dead zone X: 0x%02x 0x%02x, Y: 0x%02x 0x%02x\n", grip_buf[1],
			grip_buf[2], grip_buf[3], grip_buf[4]);

	memset(grip_buf, 0, 5);
	touch_i2c_write_byte(chip_info->client, SEC_CMD_GRIP_AREA, DEAD_ZONE_TYPE_2);
	touch_i2c_read_block(chip_info->client, SEC_CMD_GRIP_AREA, 5, grip_buf);
	seq_printf(s, "corner triangle dead zone X: 0x%02x 0x%02x, Y: 0x%02x 0x%02x\n",
			grip_buf[1], grip_buf[2], grip_buf[3], grip_buf[4]);

	memset(grip_buf, 0, 5);
	touch_i2c_write_byte(chip_info->client, SEC_CMD_GRIP_AREA, LONG_PRESS_ZONE);
	touch_i2c_read_block(chip_info->client, SEC_CMD_GRIP_AREA, 5, grip_buf);
	seq_printf(s, "conditon long press zone X: 0x%02x 0x%02x, Y: 0x%02x 0x%02x\n",
			grip_buf[1], grip_buf[2], grip_buf[3], grip_buf[4]);

	memset(grip_buf, 0, 5);
	touch_i2c_write_byte(chip_info->client, SEC_CMD_GRIP_PARA, LONG_PRESS_ZONE);
	touch_i2c_read_block(chip_info->client, SEC_CMD_GRIP_PARA, 3, grip_buf);
	seq_printf(s,
			"conditon long press zone delay time: 0x%02x , drag distance: 0x%02x\n",
			grip_buf[1], grip_buf[2]);

	memset(grip_buf, 0, 5);
	touch_i2c_write_byte(chip_info->client, SEC_CMD_GRIP_AREA,
			LARGE_TOUCH_REJECTION);
	touch_i2c_read_block(chip_info->client, SEC_CMD_GRIP_AREA, 5, grip_buf);
	seq_printf(s, "large touch zone X: 0x%02x 0x%02x, Y: 0x%02x 0x%02x\n",
			grip_buf[1], grip_buf[2], grip_buf[3], grip_buf[4]);

	memset(grip_buf, 0, 5);
	touch_i2c_write_byte(chip_info->client, SEC_CMD_GRIP_PARA,
			LARGE_TOUCH_REJECTION);
	touch_i2c_read_block(chip_info->client, SEC_CMD_GRIP_PARA, 3, grip_buf);
	seq_printf(s, "large touch zone delay time: 0x%02x , touch size: 0x%02x\n",
			grip_buf[1], grip_buf[2]);

	memset(grip_buf, 0, 5);
	touch_i2c_write_byte(chip_info->client, SEC_CMD_GRIP_AREA,
			CORNER_LONG_PRESS_ZONE);
	touch_i2c_read_block(chip_info->client, SEC_CMD_GRIP_AREA, 5, grip_buf);
	seq_printf(s, "corner long press zone X: 0x%02x 0x%02x, Y: 0x%02x 0x%02x\n",
			grip_buf[1], grip_buf[2], grip_buf[3], grip_buf[4]);

	memset(grip_buf, 0, 5);
	touch_i2c_write_byte(chip_info->client, SEC_CMD_GRIP_PARA,
			CORNER_LONG_PRESS_ZONE);
	touch_i2c_read_block(chip_info->client, SEC_CMD_GRIP_PARA, 3, grip_buf);
	seq_printf(s, "corner long press zone delay time: 0x%02x\n", grip_buf[1]);

	memset(grip_buf, 0, 5);
	touch_i2c_read_block(chip_info->client, SEC_CMD_EDGE_SCREEN, 4, grip_buf);
	seq_printf(s,
			"grip edage screen zone: 0x%02x, 0x%02x, 0x%02x direction: 0x%02x\n",
			grip_buf[0], grip_buf[1], grip_buf[2], grip_buf[3]);

	return;
}

static void sec_rtdp_start(struct chip_data_s6sy791 *chip_info)
{
	int ret = -1;
	u8 tpara[4] = {0x0B, 0x06, 0x64, 0x06};    /*scan type, mutual rawdata type, trigger threshold, self rawdata type*/

	ret = touch_i2c_write_block(chip_info->client, SEC_CMD_RTDP_ERASE, 0, NULL);

	if (ret < 0) {
		TPD_INFO("%s: erase rtdp memory failed(0x%02x)\n", __func__, ret);
	}

	sec_mdelay(1000);
	ret = touch_i2c_write_block(chip_info->client, SEC_CMD_RTDP_START, 4, tpara);

	if (ret < 0) {
		TPD_INFO("%s: start rtdp failed(0x%02x)\n", __func__, ret);
	}

	sec_mdelay(1000);
}

static int sec_rtdp_read_event(struct chip_data_s6sy791 *chip_info)
{
	int ret = -1;

	ret = touch_i2c_read_byte(chip_info->client, SEC_READ_RTDP_RESULT);
	return ret;
}

static void sec_rtdp_dump(struct seq_file *s,
		struct chip_data_s6sy791 *chip_info)
{
	uint8_t temp[2] = {0};
	uint8_t *pRead = NULL;
	int16_t nodeData = 0;
	int ret = -1, iArrayIndex = 0, framenum = 0, i = 0, j = 0, fnum = 0;
	int tx_num = chip_info->hw_res->tx_num;
	int rx_num = chip_info->hw_res->rx_num;
	const uint32_t readbytes = (tx_num + 1) * rx_num * 2;
	const uint32_t readselfbytes = ((tx_num + 1) + rx_num) * 2;

	pRead = tp_devm_kzalloc(&chip_info->client->dev, readbytes + readselfbytes,
			GFP_KERNEL);

	if (!pRead) {
		TPD_INFO("devm_kzalloc space failed\n");
		return;
	}

	ret = touch_i2c_write_block(chip_info->client, SEC_CMD_RTDP_INIT_PTR, 0, NULL);

	if (ret < 0) {
		TPD_INFO("%s: init rtdp read pointer failed\n", __func__);
	}

	ret = touch_i2c_read_block(chip_info->client, SEC_READ_RTDP_FRAMENUM, 2, temp);

	if (ret < 0) {
		TPD_INFO("%s: read rtdp frame num failed\n", __func__);
	}

	framenum = temp[0] | temp[1] << 8;

	for (fnum = 0; fnum < framenum; fnum++) {
		ret = touch_i2c_read_block(chip_info->client, SEC_READ_RTDP_DATA,
				readbytes + readselfbytes, pRead);

		if (ret < 0) {
			TPD_INFO("%s: dump rtdp data failed\n", __func__);
			goto ERR_OUT;
		}

		for (i = 0; i <  tx_num + 1; i++) {
			seq_printf(s, "\n[%2d]", i);

			for (j = 0; j < rx_num; j++) {
				iArrayIndex = i * rx_num + j;
				nodeData = (pRead[iArrayIndex * 2] << 8) | pRead[iArrayIndex * 2 + 1];
				seq_printf(s, "%4d, ", nodeData);
			}
		}

		seq_printf(s, "\n");
		iArrayIndex = (tx_num + 1) * rx_num;

		for (i = 0; i < tx_num + 1; i++) {
			nodeData = (pRead[(iArrayIndex + i) * 2] << 8) | pRead[(iArrayIndex + i) * 2 +
				1];
			seq_printf(s, "%4d, ", nodeData);
		}

		seq_printf(s, "\n");
		iArrayIndex = (tx_num + 1) * rx_num + tx_num + 1;

		for (j = 0; j < rx_num; j++) {
			nodeData = (pRead[(iArrayIndex + j) * 2] << 8) | pRead[(iArrayIndex + j) * 2 +
				1];
			seq_printf(s, "%4d, ", nodeData);
		}
	}

ERR_OUT:
	tp_devm_kfree(&chip_info->client->dev, (void **)&pRead,
			readbytes + readselfbytes);
}

static void sec_reserve_read(struct seq_file *s, void *chip_data)
{
	int state = 0;
	struct chip_data_s6sy791 *chip_info = (struct chip_data_s6sy791 *)chip_data;

	state = sec_rtdp_read_event(chip_info);

	if (0x01 == state) {    /*enabled, but not ready for reading*/
		TPD_INFO("read rtdp enabled, but not ready\n");
		return;

	} else if ((0x00 == state) || (0x0A == state)) {
		/*abnormal, need start rtdp*/
		TPD_INFO("start rtdp function\n");
		sec_rtdp_start(chip_info);

	} else if (0x0F == state) { /*ready*/
		TPD_INFO("start dump rtdp\n");
		sec_rtdp_dump(s, chip_info);
	}
}

static void sec_get_delta_data(void *chip_data, int32_t *delta_data)
{
	u8 *data = NULL;
	int16_t x = 0, y = 0, z = 0, ret = 0;
	struct chip_data_s6sy791 *chip_info = (struct chip_data_s6sy791 *)chip_data;
	int readbytes = chip_info->hw_res->tx_num * (chip_info->hw_res->rx_num) * 2;

	data = tp_devm_kzalloc(&chip_info->client->dev, readbytes, GFP_KERNEL);

	if (!data) {
		return;
	}

	ret = sec_read_mutual(chip_info, TYPE_SIGNAL_DATA, data, readbytes);

	if (ret < 0) {
		goto kfree_out;
	}

	for (x = 0; x < chip_info->hw_res->tx_num; x++) {
		for (y = chip_info->hw_res->rx_num - 1; y >= 0; y--) {
			z = chip_info->hw_res->rx_num * x + y;
			delta_data[z] = ((data[z * 2] << 8) | data[z * 2 + 1]);

			if (delta_data[z] >> 15 & 0x01) {
				delta_data[z] = delta_data[z] | 0xffff0000;
			}
		}
	}

kfree_out:
	tp_devm_kfree(&chip_info->client->dev, (void **)&data, readbytes);
	return;
}

static struct debug_info_proc_operations debug_info_proc_ops = {
	.delta_read         = sec_delta_read,
	.self_delta_read    = sec_self_delta_read,
	.baseline_read      = sec_baseline_read,
	.self_raw_read      = sec_self_raw_read,
	.main_register_read = sec_main_register_read,
	.reserve_read       = sec_reserve_read,
	.get_delta_data     = sec_get_delta_data,
};

/***************** End of implementation of debug_info proc callbacks*************************/
static void sec_swap(u8 *a, u8 *b)
{
	u8 temp = *a;
	*a = *b;
	*b = temp;
}

static void rearrange_sft_result(u8 *data, int length)
{
	int i = 0;

	for (i = 0; i < length; i += 4) {
		sec_swap(&data[i], &data[i + 3]);
		sec_swap(&data[i + 1], &data[i + 2]);
	}
}

static int secy791_execute_selftest(struct seq_file *s,
		void *chip_data,
		struct auto_testdata *sec_testdata,
		struct test_item_info *p_test_item_info)
{
	int rc = -1;
	u8 tpara[2] = {0x25, 0x40};
	u8 *rBuff = NULL;
	int i;
	int result_size = SEC_SELFTEST_REPORT_SIZE + sec_testdata->tx_num *
		sec_testdata->rx_num * 2;
	uint8_t  *data_buf;
	struct chip_data_s6sy791 *chip_info = (struct chip_data_s6sy791 *) chip_data;

	data_buf = chip_info->data_buf;

	/* save selftest result in flash */
	tpara[0] = 0x27;

	rBuff = tp_devm_kzalloc(&chip_info->client->dev, result_size, GFP_KERNEL);

	if (!rBuff) {
		seq_printf(s, "devm_kzalloc space failed\n");
		return -ENOMEM;
	}

	/*send self test cmd*/
	rc = touch_i2c_write_block(chip_info->client, SEC_CMD_SELFTEST, 2, tpara);

	if (rc < 0) {
		TPD_INFO("%s: Send selftest cmd failed!\n", __func__);
		seq_printf(s, "Send selftest cmd failed!\n");
		goto ERR_EXIT;
	}

	sec_mdelay(350);

	rc = sec_wait_for_ready(chip_info, SEC_VENDOR_ACK_SELF_TEST_DONE);

	if (rc < 0) {
		TPD_INFO("%s: Selftest execution time out!\n", __func__);
		seq_printf(s, "Selftest execution time out!\n");
		goto ERR_EXIT;
	}

	rc = touch_i2c_read_block(chip_info->client, SEC_READ_SELFTEST_RESULT,
			result_size, rBuff);

	if (rc < 0) {
		TPD_INFO("%s: read selftest relest failed\n", __func__);
		seq_printf(s, "read selftest relest failed\n");
		goto ERR_EXIT;
	}

	rearrange_sft_result(rBuff, result_size);

	sprintf(data_buf, "sec_ts : \n");
	tp_test_write(sec_testdata->fp, sec_testdata->length, data_buf,
			strlen(data_buf), sec_testdata->pos);

	for (i = 0; i < 80; i += 4) {
		if (i / 4 == 0) {
			sprintf(data_buf, "SIG: ");
			tp_test_write(sec_testdata->fp, sec_testdata->length, data_buf,
					strlen(data_buf), sec_testdata->pos);

		} else if (i / 4 == 1) {
			sprintf(data_buf, "VER: ");
			tp_test_write(sec_testdata->fp, sec_testdata->length, data_buf,
					strlen(data_buf), sec_testdata->pos);

		} else if (i / 4 == 2) {
			sprintf(data_buf, "SIZ: ");
			tp_test_write(sec_testdata->fp, sec_testdata->length, data_buf,
					strlen(data_buf), sec_testdata->pos);

		} else if (i / 4 == 3) {
			sprintf(data_buf, "CRC: ");
			tp_test_write(sec_testdata->fp, sec_testdata->length, data_buf,
					strlen(data_buf), sec_testdata->pos);

		} else if (i / 4 == 4) {
			sprintf(data_buf, "RES: ");
			tp_test_write(sec_testdata->fp, sec_testdata->length, data_buf,
					strlen(data_buf), sec_testdata->pos);

		} else if (i / 4 == 5) {
			sprintf(data_buf, "COU: ");
			tp_test_write(sec_testdata->fp, sec_testdata->length, data_buf,
					strlen(data_buf), sec_testdata->pos);

		} else if (i / 4 == 6) {
			sprintf(data_buf, "PAS: ");
			tp_test_write(sec_testdata->fp, sec_testdata->length, data_buf,
					strlen(data_buf), sec_testdata->pos);

		} else if (i / 4 == 7) {
			sprintf(data_buf, "FAI: ");
			tp_test_write(sec_testdata->fp, sec_testdata->length, data_buf,
					strlen(data_buf), sec_testdata->pos);

		} else if (i / 4 == 8) {
			sprintf(data_buf, "CHA: ");
			tp_test_write(sec_testdata->fp, sec_testdata->length, data_buf,
					strlen(data_buf), sec_testdata->pos);

		} else if (i / 4 == 9) {
			sprintf(data_buf, "AMB: ");
			tp_test_write(sec_testdata->fp, sec_testdata->length, data_buf,
					strlen(data_buf), sec_testdata->pos);

		} else if (i / 4 == 10) {
			sprintf(data_buf, "RXS: ");
			tp_test_write(sec_testdata->fp, sec_testdata->length, data_buf,
					strlen(data_buf), sec_testdata->pos);

		} else if (i / 4 == 11) {
			sprintf(data_buf, "TXS: ");
			tp_test_write(sec_testdata->fp, sec_testdata->length, data_buf,
					strlen(data_buf), sec_testdata->pos);

		} else if (i / 4 == 12) {
			sprintf(data_buf, "RXO: ");
			tp_test_write(sec_testdata->fp, sec_testdata->length, data_buf,
					strlen(data_buf), sec_testdata->pos);

		} else if (i / 4 == 13) {
			sprintf(data_buf, "TXO: ");
			tp_test_write(sec_testdata->fp, sec_testdata->length, data_buf,
					strlen(data_buf), sec_testdata->pos);

		} else if (i / 4 == 14) {
			sprintf(data_buf, "RXG: ");
			tp_test_write(sec_testdata->fp, sec_testdata->length, data_buf,
					strlen(data_buf), sec_testdata->pos);

		} else if (i / 4 == 15) {
			sprintf(data_buf, "TXG: ");
			tp_test_write(sec_testdata->fp, sec_testdata->length, data_buf,
					strlen(data_buf), sec_testdata->pos);

		} else if (i / 4 == 16) {
			sprintf(data_buf, "RXR: ");
			tp_test_write(sec_testdata->fp, sec_testdata->length, data_buf,
					strlen(data_buf), sec_testdata->pos);

		} else if (i / 4 == 17) {
			sprintf(data_buf, "TXT: ");
			tp_test_write(sec_testdata->fp, sec_testdata->length, data_buf,
					strlen(data_buf), sec_testdata->pos);

		} else if (i / 4 == 18) {
			sprintf(data_buf, "RXT: ");
			tp_test_write(sec_testdata->fp, sec_testdata->length, data_buf,
					strlen(data_buf), sec_testdata->pos);

		} else if (i / 4 == 19) {
			sprintf(data_buf, "TXR: ");
			tp_test_write(sec_testdata->fp, sec_testdata->length, data_buf,
					strlen(data_buf), sec_testdata->pos);
		}

		sprintf(data_buf, "0x%02X, 0x%02X, 0x%02X, 0x%02X \n", rBuff[i], rBuff[i + 1],
				rBuff[i + 2], rBuff[i + 3]);
		tp_test_write(sec_testdata->fp, sec_testdata->length, data_buf,
				strlen(data_buf), sec_testdata->pos);

		if (i / 4 == 4) {
			/* RX, RX open check. */
			if ((rBuff[i + 3] & 0x30) != 0) {
				rc = 0;
				seq_printf(s, "RX, RX open check failed\n");
			}

			/* TX, RX GND(VDD) short check. */
			else if ((rBuff[i + 3] & 0xC0) != 0) {
				rc = 0;
				seq_printf(s, "TX, RX GND(VDD) short check failed\n");
			}

			/* RX-RX, TX-TX short check. */
			else if ((rBuff[i + 2] & 0x03) != 0) {
				rc = 0;
				seq_printf(s, "RX-RX, TX-TX short check failed\n");
			}

			/* TX-RX short check. */
			else if ((rBuff[i + 2] & 0x04) != 0) {
				rc = 0;
				seq_printf(s, "TX-RX short check failed\n");

			} else {
				rc = 1;
			}
		}
	}

	sprintf(data_buf, "\n");
	tp_test_write(sec_testdata->fp, sec_testdata->length, data_buf,
			strlen(data_buf), sec_testdata->pos);

ERR_EXIT:
	tp_devm_kfree(&chip_info->client->dev, (void **)&rBuff, result_size);
	return rc;
}

static int secy791_execute_p2ptest(struct seq_file *s,
		void *chip_data,
		struct auto_testdata *sec_testdata,
		struct test_item_info *p_test_item_info)
{
	int rc;
	u8 tpara[2] = {0x0F, 0x11};
	struct chip_data_s6sy791 *chip_info = (struct chip_data_s6sy791 *)chip_data;

	TPD_INFO("%s: P2P test start!\n", __func__);
	rc = touch_i2c_write_block(chip_info->client, SEC_CMD_SET_P2PTEST_MODE, 2,
			tpara);

	if (rc < 0) {
		seq_printf(s, "%s: Send P2Ptest Mode cmd failed!\n", __func__);
		goto err_exit;
	}

	sec_mdelay(15);

	tpara[0] = 0x00;
	tpara[1] = 0x64;
	rc = touch_i2c_write_block(chip_info->client, SEC_CMD_P2PTEST, 2, tpara);

	if (rc < 0) {
		seq_printf(s, "%s: Send P2Ptest cmd failed!\n", __func__);
		goto err_exit;
	}

	sec_mdelay(1000);

	rc = sec_wait_for_ready(chip_info, SEC_VENDOR_ACK_P2P_TEST_DONE);

	if (rc < 0) {
		seq_printf(s, "%s: P2Ptest execution time out!\n", __func__);
		goto err_exit;
	}

	TPD_INFO("%s: P2P test done!\n", __func__);

err_exit:
	return rc;
}

static int sec_get_verify_result(struct chip_data_s6sy791 *chip_info)
{
	int ret = -1;

	sec_fix_tmode(chip_info, TOUCH_SYSTEM_MODE_TOUCH, TOUCH_MODE_STATE_TOUCH);
	touch_i2c_write_block(chip_info->client, 0xA7, 0,
			NULL);    /*set to verify calibration*/
	sec_mdelay(100);
	/*get calibration result, 0x0F:FAIL(bit[0]:data condition FAIL, bit[1]:RX gap FAIL, bit[2]:TX gap FAIL, bit[3]:TX/RX peak FAIL)*/
	ret = touch_i2c_read_byte(chip_info->client, 0xA8);
	sec_release_tmode(chip_info);

	return ret;
}

static void sec_calibrate(struct seq_file *s, void *chip_data)
{
	int ret = -1;
	struct chip_data_s6sy791 *chip_info = (struct chip_data_s6sy791 *)chip_data;

	ret = sec_execute_force_calibration(chip_info);

	if (ret < 0) {
		TPD_INFO("1 error, do calibration failed\n");
		seq_printf(s, "1 error, do calibration failed\n");
		return;
	}

	if (check_calibration(chip_info)) {
		chip_info->cal_needed = true;
		TPD_INFO("1 error, check calibration failed\n");
		seq_printf(s, "1 error, check calibration failed\n");
		return;

	} else {
		chip_info->cal_needed = false;
	}

	ret = sec_get_verify_result(chip_info);

	if (ret) {
		seq_printf(s, "1 error, calibration verify failed(%d)\n", ret);

	} else {
		seq_printf(s, "0 error, calibration and verify success\n");
	}

	TPD_INFO("get verify result :%d\n", ret);

	return;
}

static void sec_verify_calibration(struct seq_file *s, void *chip_data)
{
	int ret = -1;
	struct chip_data_s6sy791 *chip_info = (struct chip_data_s6sy791 *)chip_data;

	ret = sec_get_verify_result(chip_info);

	if (ret != 0) {
		seq_printf(s, "1 error, verify calibration result failed(0x%02x)\n", ret);

	} else {
		seq_printf(s, "0 error, verify calibration result successed\n");
	}

	return;
}

static bool sec_get_cal_status(struct seq_file *s, void *chip_data)
{
	struct chip_data_s6sy791 *chip_info = (struct chip_data_s6sy791 *)chip_data;

	return chip_info->cal_needed;
}

static int secy791_mutual_raw_test(struct seq_file *s, void *chip_data,
		struct auto_testdata *sec_testdata,
		struct test_item_info *p_test_item_info)
{
	u8 type = 0;
	uint32_t err_cnt = 0;
	int16_t nodeData = 0, Buff16 = 0, Buff16_2 = 0, nodeGap = 0;
	int i = 0, j = 0, iArrayIndex = 0, iArrayIndex_2 = 0, ret = -1;
	int32_t *p_mutual_p = NULL, *p_mutual_n = NULL, *p_mutualGap_p = NULL,
		*p_mutualGap_n = NULL;
	struct chip_data_s6sy791 *chip_info = (struct chip_data_s6sy791 *)chip_data;
	uint8_t *pRead;
	uint8_t  *data_buf;

	pRead = chip_info->pRead;
	data_buf = chip_info->data_buf;

	if (p_test_item_info->para_num) {
		if (p_test_item_info->p_buffer[0]) {
			if (p_test_item_info->item_limit_type == LIMIT_TYPE_EACH_NODE_DATA) {
				p_mutual_p = (int32_t *)(sec_testdata->fw->data +
						p_test_item_info->top_limit_offset);
				p_mutualGap_p = (int32_t *)(sec_testdata->fw->data +
						p_test_item_info->top_limit_offset + 4 * sec_testdata->tx_num *
						sec_testdata->rx_num);
				p_mutual_n = (int32_t *)(sec_testdata->fw->data +
						p_test_item_info->floor_limit_offset);
				p_mutualGap_n = (int32_t *)(sec_testdata->fw->data +
						p_test_item_info->floor_limit_offset + 4 * sec_testdata->tx_num *
						sec_testdata->rx_num);

			} else {
				err_cnt++;
				TPD_INFO("item: %d has invalid limit type(%d)\n", TYPE_TEST2,
						p_test_item_info->item_limit_type);
				seq_printf(s, "item: %d has invalid limit type(%d)\n", TYPE_TEST2,
						p_test_item_info->item_limit_type);
				return -1;
			}
		}
	}

	/* set reference data */
	type = TYPE_OFFSET_DATA_SDC;
	ret = touch_i2c_write_byte(chip_info->client, SEC_CMD_MUTU_RAW_TYPE, type);

	if (ret < 0) {
		err_cnt++;
		TPD_INFO("%s: set OFFSET_DATA_SEC type failed\n", __func__);
		seq_printf(s, "set OFFSET_DATA_SEC type failed\n");
		return -1;
	}

	sec_mdelay(50);

	/* read reference data */
	ret = touch_i2c_read_block(chip_info->client, SEC_READ_TOUCH_RAWDATA,
			chip_info->readbytes, pRead);

	if (ret < 0) {
		err_cnt++;
		TPD_INFO("%s: read mutual rawdata failed!\n", __func__);
		seq_printf(s, "read mutual rawdata failed\n");
		return -1;
	}

	/* store and judge reference data */
	sprintf(data_buf, "TYPE_MUTUAL_RAW_OFFSET_DATA_SDC:\n");
	tp_test_write(sec_testdata->fp, sec_testdata->length, data_buf,
			strlen(data_buf), sec_testdata->pos);

	for (i = 0; i <  sec_testdata->tx_num; i++) {
		for (j = 0; j <  sec_testdata->rx_num; j++) {
			iArrayIndex = i * sec_testdata->rx_num + j;
			nodeData = (pRead[iArrayIndex * 2] << 8) | pRead[iArrayIndex * 2 + 1];

			if (!IS_ERR_OR_NULL(sec_testdata->fp)) {
				sprintf(data_buf, "%d, ", nodeData);
				tp_test_write(sec_testdata->fp, sec_testdata->length, data_buf,
						strlen(data_buf), sec_testdata->pos);
			}

			if ((nodeData < p_mutual_n[iArrayIndex])
					|| (nodeData > p_mutual_p[iArrayIndex])) {
				TPD_INFO(" mutual offset_data failed at data[%d][%d] = %d [%d,%d]\n", i, j,
						nodeData, p_mutual_n[iArrayIndex], p_mutual_p[iArrayIndex]);

				if (!err_cnt) {
					seq_printf(s, "mutual offset_data failed at data[%d][%d] = %d [%d,%d]\n", i, j,
							nodeData, p_mutual_n[iArrayIndex], p_mutual_p[iArrayIndex]);
				}

				err_cnt++;
			}
		}

		if (!IS_ERR_OR_NULL(sec_testdata->fp)) {
			sprintf(data_buf, "\n");
			tp_test_write(sec_testdata->fp, sec_testdata->length, data_buf,
					strlen(data_buf), sec_testdata->pos);
		}
	}

	/* CM Offseet gap (left-right)*/
	sprintf(data_buf, "left-right gap:\n");
	tp_test_write(sec_testdata->fp, sec_testdata->length, data_buf,
			strlen(data_buf), sec_testdata->pos);

	for (i = 0; i < sec_testdata->tx_num - 1; i++) {
		for (j = 0; j < sec_testdata->rx_num; j++) {
			iArrayIndex = i * sec_testdata->rx_num + j;
			iArrayIndex_2 = (i + 1) * sec_testdata->rx_num + j;
			Buff16 = (pRead[iArrayIndex * 2] << 8) | pRead[iArrayIndex * 2 + 1];
			Buff16_2 = (pRead[iArrayIndex_2 * 2] << 8) | pRead[iArrayIndex_2 * 2 + 1];

			if (Buff16 > Buff16_2) {
				nodeGap = 100 - (Buff16_2 * 100 / Buff16);

			} else {
				nodeGap = 100 - (Buff16 * 100 / Buff16_2);
			}

			if (!IS_ERR_OR_NULL(sec_testdata->fp)) {
				sprintf(data_buf, "%d, ", nodeGap);
				tp_test_write(sec_testdata->fp, sec_testdata->length, data_buf,
						strlen(data_buf), sec_testdata->pos);
			}

			if ((nodeGap > p_mutualGap_p[iArrayIndex])
					|| (nodeGap < p_mutualGap_n[iArrayIndex])) {
				TPD_INFO("mutual node[%d, %d]=%d and node[%d, %d]=%d gap beyond [%d, %d]\n", i,
						j, Buff16, i + 1, j, Buff16_2, p_mutualGap_n[iArrayIndex],
						p_mutualGap_p[iArrayIndex]);

				if (!err_cnt) {
					seq_printf(s,
							"mutual node[%d, %d]=%d and node[%d, %d]=%d gap beyond [%d, %d]\n", i, j,
							Buff16, i + 1, j, Buff16_2, p_mutualGap_n[iArrayIndex],
							p_mutualGap_p[iArrayIndex]);
				}

				err_cnt++;
			}
		}

		if (!IS_ERR_OR_NULL(sec_testdata->fp)) {
			sprintf(data_buf, "\n");
			tp_test_write(sec_testdata->fp, sec_testdata->length, data_buf,
					strlen(data_buf), sec_testdata->pos);
		}
	}

	/* CM Offseet gap (up-down)*/
	sprintf(data_buf, "up-down gap:\n");
	tp_test_write(sec_testdata->fp, sec_testdata->length, data_buf,
			strlen(data_buf), sec_testdata->pos);

	for (i = 0; i < sec_testdata->tx_num; i++) {
		for (j = 0; j < sec_testdata->rx_num - 1; j++) {
			iArrayIndex = i * sec_testdata->rx_num + j;
			iArrayIndex_2 = i * sec_testdata->rx_num + j + 1;
			Buff16 = (pRead[iArrayIndex * 2] << 8) | pRead[iArrayIndex * 2 + 1];
			Buff16_2 = (pRead[iArrayIndex_2 * 2] << 8) | pRead[iArrayIndex_2 * 2 + 1];

			if (Buff16 > Buff16_2) {
				nodeGap = 100 - (Buff16_2 * 100 / Buff16);

			} else {
				nodeGap = 100 - (Buff16 * 100 / Buff16_2);
			}

			if (!IS_ERR_OR_NULL(sec_testdata->fp)) {
				sprintf(data_buf,  "%d, ", nodeGap);
				tp_test_write(sec_testdata->fp, sec_testdata->length, data_buf,
						strlen(data_buf), sec_testdata->pos);
			}

			if ((nodeGap > p_mutualGap_p[iArrayIndex])
					|| (nodeGap < p_mutualGap_n[iArrayIndex])) {
				TPD_INFO("mutual node[%d, %d]=%d and node[%d, %d]=%d gap beyond [%d, %d]\n", j,
						i, Buff16, j + 1, i, Buff16_2, p_mutualGap_n[iArrayIndex],
						p_mutualGap_p[iArrayIndex]);

				if (!err_cnt) {
					seq_printf(s,
							"mutual node[%d, %d]=%d and node[%d, %d]=%d gap beyond [%d, %d]\n", j, i,
							Buff16, j + 1, i, Buff16_2, p_mutualGap_n[iArrayIndex],
							p_mutualGap_p[iArrayIndex]);
				}

				err_cnt++;
			}
		}

		if (!IS_ERR_OR_NULL(sec_testdata->fp)) {
			sprintf(data_buf, "\n");
			tp_test_write(sec_testdata->fp, sec_testdata->length, data_buf,
					strlen(data_buf), sec_testdata->pos);
		}
	}

	return -err_cnt;
}

static int secy791_self_offset_test(struct seq_file *s, void *chip_data,
		struct auto_testdata *sec_testdata,
		struct test_item_info *p_test_item_info)
{
	u8 type = 0;
	uint32_t err_cnt = 0;
	int16_t nodeData = 0;
	int i = 0, ret = -1;
	int32_t *p_tx_offset_p = NULL, *p_tx_offset_n = NULL, *p_rx_offset_p = NULL,
		*p_rx_offset_n = NULL;
	struct chip_data_s6sy791 *chip_info = (struct chip_data_s6sy791 *)chip_data;
	uint8_t *pRead;
	uint8_t  *data_buf;

	pRead = chip_info->pRead;
	data_buf = chip_info->data_buf;

	if (p_test_item_info->para_num) {
		if (p_test_item_info->p_buffer[0]) {
			if (p_test_item_info->item_limit_type == LIMIT_TYPE_SLEF_TX_RX_DATA_DOUBLE) {
				p_tx_offset_p = (int32_t *)(sec_testdata->fw->data +
						p_test_item_info->top_limit_offset);
				p_tx_offset_n = (int32_t *)(sec_testdata->fw->data +
						p_test_item_info->top_limit_offset + 4 * sec_testdata->tx_num);
				p_rx_offset_p = (int32_t *)(sec_testdata->fw->data +
						p_test_item_info->top_limit_offset + 2 * 4 * sec_testdata->tx_num);
				p_rx_offset_n = (int32_t *)(sec_testdata->fw->data +
						p_test_item_info->top_limit_offset + 2 * 4 * sec_testdata->tx_num + 4 *
						sec_testdata->rx_num);

			} else {
				err_cnt++;
				TPD_INFO("item: %d has invalid limit type(%d)\n", TYPE_TEST3,
						p_test_item_info->item_limit_type);
				seq_printf(s, "item: %d has invalid limit type(%d)\n", TYPE_TEST3,
						p_test_item_info->item_limit_type);
				return -err_cnt;
			}
		}
	}

	/* check self offset data */
	type = TYPE_OFFSET_DATA_SDC;
	ret = touch_i2c_write_byte(chip_info->client, SEC_CMD_SELF_RAW_TYPE, type);

	if (ret < 0) {
		err_cnt++;
		TPD_INFO("%s: set self rawdata type failed\n", __func__);
		seq_printf(s, "set self rawdata type failed\n");
		return -err_cnt;
	}

	sec_mdelay(100);
	/* read raw data */
	memset(pRead, 0, (sec_testdata->tx_num * sec_testdata->rx_num *
				2)); /*clear buffer*/
	ret = touch_i2c_read_block(chip_info->client, SEC_READ_TOUCH_SELF_RAWDATA,
			chip_info->readselfbytes, pRead);

	if (ret < 0) {
		err_cnt++;
		TPD_INFO("%s: read self rawdata failed!\n", __func__);
		seq_printf(s, "read self rawdata failed\n");
		return -err_cnt;
	}

	/* store and judge self minimum frame data */
	sprintf(data_buf, "TYPE_SELF_TX_OFFSET_DATA:\n");
	tp_test_write(sec_testdata->fp, sec_testdata->length, data_buf,
			strlen(data_buf), sec_testdata->pos);

	/* check long channel of self data	*/
	for (i = 0; i < sec_testdata->tx_num; i++) {
		nodeData = (pRead[i * 2] << 8) | pRead[i * 2 + 1];

		if (!IS_ERR_OR_NULL(sec_testdata->fp)) {
			sprintf(data_buf, "%d, ", nodeData);
			tp_test_write(sec_testdata->fp, sec_testdata->length, data_buf,
					strlen(data_buf), sec_testdata->pos);
		}

		if ((nodeData < p_tx_offset_n[i]) || (nodeData > p_tx_offset_p[i])) {
			TPD_INFO("self_offset_tx_data failed at data[%d] = %d [%d,%d]\n", i, nodeData,
					p_tx_offset_n[i], p_tx_offset_p[i]);

			if (!err_cnt) {
				seq_printf(s, "self_offset_tx_data failed at data[%d] = %d [%d,%d]\n", i,
						nodeData, p_tx_offset_n[i], p_tx_offset_p[i]);
			}

			err_cnt++;
		}
	}

	sprintf(data_buf, "\n");
	tp_test_write(sec_testdata->fp, sec_testdata->length, data_buf,
			strlen(data_buf), sec_testdata->pos);

	sprintf(data_buf, "TYPE_SELF_RX_OFFSET_DATA:\n");
	tp_test_write(sec_testdata->fp, sec_testdata->length, data_buf,
			strlen(data_buf), sec_testdata->pos);

	/* check short channel of self data */
	for (i = 0; i < sec_testdata->rx_num; i++) {
		nodeData = (pRead[sec_testdata->tx_num * 2 + i * 2] << 8) |
			pRead[sec_testdata->tx_num * 2 + i * 2 + 1];

		if (!IS_ERR_OR_NULL(sec_testdata->fp)) {
			sprintf(data_buf, "%d, ", nodeData);
			tp_test_write(sec_testdata->fp, sec_testdata->length, data_buf,
					strlen(data_buf), sec_testdata->pos);
		}

		if ((nodeData < p_rx_offset_n[i]) || (nodeData > p_rx_offset_p[i])) {
			TPD_INFO("self_offset_rx_data failed at data[%d] = %d [%d,%d]\n", i, nodeData,
					p_rx_offset_n[i], p_rx_offset_p[i]);

			if (!err_cnt) {
				seq_printf(s, "self_offset_rx_data failed at data[%d] = %d [%d,%d]\n", i,
						nodeData, p_rx_offset_n[i], p_rx_offset_p[i]);
			}

			err_cnt++;
		}

		if (!IS_ERR_OR_NULL(sec_testdata->fp)) {
			sprintf(data_buf, "%d, ", nodeData);
			tp_test_write(sec_testdata->fp, sec_testdata->length, data_buf,
					strlen(data_buf), sec_testdata->pos);
		}
	}

	sprintf(data_buf, "\n");
	tp_test_write(sec_testdata->fp, sec_testdata->length, data_buf,
			strlen(data_buf), sec_testdata->pos);
	return -err_cnt;
}

static int secy791_mutual_raw_noise_test(struct seq_file *s, void *chip_data,
		struct auto_testdata *sec_testdata,
		struct test_item_info *p_test_item_info)
{
	u8 type = 0;
	uint32_t err_cnt = 0;
	int16_t nodeData = 0;
	int i = 0, j = 0, iArrayIndex = 0, ret = -1;
	int32_t *p_p2p_p = NULL, *p_p2p_n = NULL;
	struct chip_data_s6sy791 *chip_info = (struct chip_data_s6sy791 *)chip_data;
	uint8_t *pRead;
	uint8_t  *data_buf;

	pRead = chip_info->pRead;
	data_buf = chip_info->data_buf;

	if (p_test_item_info->para_num) {
		if (p_test_item_info->p_buffer[0]) {
			if (p_test_item_info->item_limit_type == LIMIT_TYPE_TX_RX_DATA) {
				p_p2p_p = (int32_t *)(sec_testdata->fw->data +
						p_test_item_info->top_limit_offset);
				p_p2p_n = (int32_t *)(sec_testdata->fw->data +
						p_test_item_info->floor_limit_offset);

			} else {
				err_cnt++;
				TPD_INFO("item: %d has invalid limit type(%d)\n", TYPE_TEST5,
						p_test_item_info->item_limit_type);
				seq_printf(s, "item: %d has invalid limit type(%d)\n", TYPE_TEST5,
						p_test_item_info->item_limit_type);
				return -err_cnt;
			}
		}
	}

	/* read minimum value frame from p2p test result */
	type = TYPE_NOI_P2P_MIN;
	ret = touch_i2c_write_byte(chip_info->client, SEC_CMD_MUTU_RAW_TYPE, type);

	if (ret < 0) {
		err_cnt++;
		TPD_INFO("%s: set rawdata type failed\n", __func__);
		seq_printf(s, "set rawdata type failed\n");
		return -err_cnt;
	}

	sec_mdelay(100);
	/* read raw data */
	memset(pRead, 0, chip_info->readbytes); /*clear buffer*/
	ret = touch_i2c_read_block(chip_info->client, SEC_READ_TOUCH_RAWDATA,
			chip_info->readbytes, pRead);

	if (ret < 0) {
		err_cnt++;
		TPD_INFO("%s: read rawdata failed!\n", __func__);
		seq_printf(s, "read rawdata failed\n");
		return -err_cnt;
	}

	sprintf(data_buf, "TYPE_P2P_MIN_DATA:\n");
	tp_test_write(sec_testdata->fp, sec_testdata->length, data_buf,
			strlen(data_buf), sec_testdata->pos);

	/* check minimum value */
	for (i = 0; i < sec_testdata->tx_num; i++) {
		for (j = 0; j < sec_testdata->rx_num; j++) {
			iArrayIndex = i * sec_testdata->rx_num + j;
			nodeData = (pRead[iArrayIndex * 2] << 8) | pRead[iArrayIndex * 2 + 1];

			if (!IS_ERR_OR_NULL(sec_testdata->fp)) {
				sprintf(data_buf, "%d, ", nodeData);
				tp_test_write(sec_testdata->fp, sec_testdata->length, data_buf,
						strlen(data_buf), sec_testdata->pos);
			}

			if ((nodeData < p_p2p_n[iArrayIndex])) {
				TPD_INFO("p2p_min_data failed at data[%d][%d] = %d [%d]\n", i, j, nodeData,
						p_p2p_n[iArrayIndex]);

				if (!err_cnt) {
					seq_printf(s, "p2p_min_data failed at data[%d][%d] = %d [%d]\n", i, j, nodeData,
							p_p2p_n[iArrayIndex]);
				}

				err_cnt++;
			}
		}

		if (!IS_ERR_OR_NULL(sec_testdata->fp)) {
			sprintf(data_buf, "\n");
			tp_test_write(sec_testdata->fp, sec_testdata->length, data_buf,
					strlen(data_buf), sec_testdata->pos);
		}
	}

	/* read maximum value frame from p2p test result */
	type = TYPE_NOI_P2P_MAX;
	ret = touch_i2c_write_byte(chip_info->client, SEC_CMD_MUTU_RAW_TYPE, type);

	if (ret < 0) {
		err_cnt++;
		TPD_INFO("%s: set rawdata type failed\n", __func__);
		seq_printf(s, "set rawdata type failed\n");
		return -err_cnt;
	}

	sec_mdelay(100);
	/* read raw data */
	memset(pRead, 0, chip_info->readbytes); /*clear buffer*/
	ret = touch_i2c_read_block(chip_info->client, SEC_READ_TOUCH_RAWDATA,
			chip_info->readbytes, pRead);

	if (ret < 0) {
		err_cnt++;
		TPD_INFO("%s: read rawdata failed!\n", __func__);
		seq_printf(s, "read rawdata failed\n");
		return -err_cnt;
	}

	sprintf(data_buf, "TYPE_P2P_MAX_DATA:\n");
	tp_test_write(sec_testdata->fp, sec_testdata->length, data_buf,
			strlen(data_buf), sec_testdata->pos);

	/* check maximum value */
	for (i = 0; i < sec_testdata->tx_num; i++) {
		for (j = 0; j < sec_testdata->rx_num; j++) {
			iArrayIndex = i * sec_testdata->rx_num + j;
			nodeData = (pRead[iArrayIndex * 2] << 8) | pRead[iArrayIndex * 2 + 1];

			if (!IS_ERR_OR_NULL(sec_testdata->fp)) {
				sprintf(data_buf, "%d, ", nodeData);
				tp_test_write(sec_testdata->fp, sec_testdata->length, data_buf,
						strlen(data_buf), sec_testdata->pos);
			}

			if ((nodeData > p_p2p_p[iArrayIndex])) {
				TPD_INFO("p2p_max_data failed at data[%d][%d] = %d [%d]\n", i, j, nodeData,
						p_p2p_p[iArrayIndex]);

				if (!err_cnt) {
					seq_printf(s, "p2p_max_data failed at data[%d][%d] = %d [%d]\n", i, j, nodeData,
							p_p2p_p[iArrayIndex]);
				}

				err_cnt++;
			}
		}

		if (!IS_ERR_OR_NULL(sec_testdata->fp)) {
			sprintf(data_buf, "\n");
			tp_test_write(sec_testdata->fp, sec_testdata->length, data_buf,
					strlen(data_buf), sec_testdata->pos);
		}
	}

	return -err_cnt;
}

static int secy791_test_disable_interrupt(void *chip_data, bool enable)
{
	int ret = 0;
	struct chip_data_s6sy791 *chip_info = (struct chip_data_s6sy791 *)chip_data;

	ret = touch_i2c_write_byte(chip_info->client, SEC_CMD_INTERRUPT_SWITCH, enable);
	TPD_INFO("%s: disable irq enable: %d %s!\n", __func__, enable,
			ret < 0 ? "failed" : "success");

	if (enable == true) {
		ret = touch_i2c_write_block(chip_info->client, SEC_CMD_CLEAR_EVENT_STACK, 0,
				NULL);

		if (ret < 0) {
			TPD_INFO("%s: write sec clear event failed.\n", __func__);
			return -1;
		}
	}

	return ret;
}

static int secy791_get_verify_result(void *chip_data)
{
	int ret = -1;
	struct chip_data_s6sy791 *chip_info = (struct chip_data_s6sy791 *)chip_data;

	ret = sec_get_verify_result(chip_info);

	return ret;
}

static int sec_auto_test_preoperation(struct seq_file *s, void *chip_data,
		struct auto_testdata *sec_testdata,
		struct test_item_info *p_test_item_info)
{
	struct chip_data_s6sy791        *chip_info = (struct chip_data_s6sy791 *)
		chip_data;

	chip_info->readbytes = sec_testdata->tx_num * sec_testdata->rx_num * 2;
	chip_info->pRead = tp_devm_kzalloc(&chip_info->client->dev,
			chip_info->readbytes, GFP_KERNEL);

	if (!chip_info->pRead) {
		TPD_INFO("raw_data kzalloc error\n");
		return -1;
	}

	chip_info->data_buf_size = 64;
	chip_info->data_buf = kzalloc(chip_info->data_buf_size, GFP_KERNEL);

	if (!chip_info->data_buf) {
		TPD_INFO("raw_data kzalloc error\n");
		return -1;
	}

	chip_info->readselfbytes = (sec_testdata->tx_num + sec_testdata->rx_num) * 2;

	return 0;
}

static int sec_auto_test_endoperation(struct seq_file *s, void *chip_data,
		struct auto_testdata *sec_testdata,
		struct test_item_info *p_test_item_info)
{
	struct chip_data_s6sy791        *chip_info = (struct chip_data_s6sy791 *)
		chip_data;

	tp_devm_kfree(&chip_info->client->dev, (void **)&chip_info->pRead,
			chip_info->readbytes);
	kfree(chip_info->data_buf);

	return 0;
}

static struct sec_auto_test_operations sec_test_ops = {
	.test1        =  secy791_execute_selftest,
	.test2        =  secy791_mutual_raw_test,
	.test3        =  secy791_self_offset_test,
	.test4        =  secy791_execute_p2ptest,
	.test5        =  secy791_mutual_raw_noise_test,
	.sec_get_verify_result       =  secy791_get_verify_result,
	.sec_auto_test_disable_irq   =  secy791_test_disable_interrupt,
	.sec_auto_test_preoperation = sec_auto_test_preoperation,
	.sec_auto_test_endoperation = sec_auto_test_endoperation,
};

static struct engineer_test_operations sec_engineer_test_ops = {
	.auto_test                  = sec_auto_test,
};
/*************************************auto test Funtion**************************************/

/*********** Start of kernel grip callbacks*************************/

static int ver_bottom_large_handle_func(struct chip_data_s6sy791 *chip_info,
		struct grip_zone_area *grip_zone, bool enable)
{
	int ret = 0;
	u8 area_size[5] = {CORNER_LONG_PRESS_ZONE, 0, 0, 0, 0};

	if (!chip_info || !grip_zone || *chip_info->in_suspend) {
		return -1;
	}

	if (enable) {
		if ((grip_zone->grip_side >> TYPE_LONG_CORNER_SIDE) & 0x01) {
			area_size[1] = (grip_zone->x_width >> 8) & 0xFF;
			area_size[2] = grip_zone->x_width & 0xFF;
			area_size[3] = (grip_zone->y_width >> 8) & 0xFF;
			area_size[4] = grip_zone->y_width & 0xFF;

		} else if ((grip_zone->grip_side >> TYPE_SHORT_CORNER_SIDE) & 0x01) {
			area_size[1] = (grip_zone->y_width >> 8) & 0xFF;
			area_size[2] = grip_zone->y_width & 0xFF;
			area_size[3] = (grip_zone->x_width >> 8) & 0xFF;
			area_size[4] = grip_zone->x_width & 0xFF;

		} else if ((grip_zone->grip_side >> TYPE_LONG_SIDE) & 0x01) {
			area_size[1] = (grip_zone->x_width >> 8) & 0xFF;
			area_size[2] = grip_zone->x_width & 0xFF;

		} else if ((grip_zone->grip_side >> TYPE_SHORT_SIDE) & 0x01) {
			area_size[1] = (grip_zone->y_width >> 8) & 0xFF;
			area_size[2] = grip_zone->y_width & 0xFF;
		}
	}

	ret = touch_i2c_write_byte(chip_info->client, SEC_CMD_GRIP_DIRECTION, 0x00);
	ret |= touch_i2c_write_block(chip_info->client, SEC_CMD_GRIP_AREA,
			sizeof(area_size), area_size);
	ret |= touch_i2c_write_byte(chip_info->client, SEC_CMD_GRIP_DIRECTION,
			chip_info->touch_direction);
	TPD_DETAIL("%s: cmd write is : 0x%02x, 0x%02x, 0x%02x, 0x%02x, 0x%02x, 0x%02x.\n",
			__func__, SEC_CMD_GRIP_AREA,
			area_size[0], area_size[1], area_size[2], area_size[3], area_size[4]);
	TPD_DETAIL("%s: %s area size is %s %s in fw : [%d, %d] [%d %d].\n", __func__,
			grip_zone->name, ret < 0 ? "failed" : "success", enable ? "change" : "remove",
			grip_zone->start_x, grip_zone->start_y,
			grip_zone->x_width, grip_zone->y_width);

	return ret;
}

static int hor_corner_large_handle_func(struct chip_data_s6sy791 *chip_info,
		struct grip_zone_area *grip_zone, bool enable)
{
	int ret = 0;
	u8 area_size[5] = {CORNER_LONG_PRESS_ZONE, 0, 0, 0, 0};

	if (!chip_info || !grip_zone || *chip_info->in_suspend) {
		return -1;
	}

	if (enable) {
		if ((grip_zone->grip_side >> TYPE_LONG_CORNER_SIDE) & 0x01) {
			area_size[1] = (grip_zone->x_width >> 8) & 0xFF;
			area_size[2] = grip_zone->x_width & 0xFF;
			area_size[3] = (grip_zone->y_width >> 8) & 0xFF;
			area_size[4] = grip_zone->y_width & 0xFF;

		} else if ((grip_zone->grip_side >> TYPE_SHORT_CORNER_SIDE) & 0x01) {
			area_size[1] = (grip_zone->y_width >> 8) & 0xFF;
			area_size[2] = grip_zone->y_width & 0xFF;
			area_size[3] = (grip_zone->x_width >> 8) & 0xFF;
			area_size[4] = grip_zone->x_width & 0xFF;

		} else if ((grip_zone->grip_side >> TYPE_LONG_SIDE) & 0x01) {
			area_size[1] = (grip_zone->x_width >> 8) & 0xFF;
			area_size[2] = grip_zone->x_width & 0xFF;

		} else if ((grip_zone->grip_side >> TYPE_SHORT_SIDE) & 0x01) {
			area_size[1] = (grip_zone->y_width >> 8) & 0xFF;
			area_size[2] = grip_zone->y_width & 0xFF;
		}
	}

	ret = touch_i2c_write_byte(chip_info->client, SEC_CMD_GRIP_DIRECTION, 0x01);
	ret |= touch_i2c_write_block(chip_info->client, SEC_CMD_GRIP_AREA,
			sizeof(area_size), area_size);
	ret |= touch_i2c_write_byte(chip_info->client, SEC_CMD_GRIP_DIRECTION,
			chip_info->touch_direction);
	TPD_DETAIL("%s: cmd write is : 0x%02x, 0x%02x, 0x%02x, 0x%02x, 0x%02x, 0x%02x.\n",
			__func__, SEC_CMD_GRIP_AREA,
			area_size[0], area_size[1], area_size[2], area_size[3], area_size[4]);
	TPD_DETAIL("%s: %s area size is %s %s in fw : [%d, %d] [%d %d].\n", __func__,
			grip_zone->name, ret < 0 ? "failed" : "success", enable ? "change" : "remove",
			grip_zone->start_x, grip_zone->start_y,
			grip_zone->x_width, grip_zone->y_width);

	return ret;
}

static int long_size_dead_zone_handle_func(struct chip_data_s6sy791 *chip_info,
		struct grip_zone_area *grip_zone, bool enable)
{
	int ret = 0;
	u8 area_size[5] = {DEAD_ZONE_TYPE_1, 0, 0, 0xFF, 0xFF};

	if (!chip_info || !grip_zone || *chip_info->in_suspend) {
		return -1;
	}

	if (enable) {
		if ((grip_zone->grip_side >> TYPE_LONG_SIDE) & 0x01) {
			area_size[1] = (grip_zone->x_width >> 8) & 0xFF;
			area_size[2] = grip_zone->x_width & 0xFF;

		} else if ((grip_zone->grip_side >> TYPE_SHORT_SIDE) & 0x01) {
			area_size[1] = (grip_zone->y_width >> 8) & 0xFF;
			area_size[2] = grip_zone->y_width & 0xFF;
		}
	}

	ret = touch_i2c_write_block(chip_info->client, SEC_CMD_GRIP_AREA,
			sizeof(area_size), area_size);
	TPD_DETAIL("%s: cmd write is : 0x%02x, 0x%02x, 0x%02x, 0x%02x, 0x%02x, 0x%02x.\n",
			__func__, SEC_CMD_GRIP_AREA,
			area_size[0], area_size[1], area_size[2], area_size[3], area_size[4]);
	TPD_DETAIL("%s: %s area size is %s %s in fw : [%d, %d] [%d %d].\n", __func__,
			grip_zone->name, ret < 0 ? "failed" : "success", enable ? "change" : "remove",
			grip_zone->start_x, grip_zone->start_y,
			grip_zone->x_width, grip_zone->y_width);

	return ret;
}

static int short_size_dead_zone_handle_func(struct chip_data_s6sy791 *chip_info,
		struct grip_zone_area *grip_zone, bool enable)
{
	int ret = 0;
	u8 area_size[5] = {DEAD_ZONE_TYPE_1, 0xFF, 0xFF, 0, 0};

	if (!chip_info || !grip_zone || *chip_info->in_suspend) {
		return -1;
	}

	if (enable) {
		if ((grip_zone->grip_side >> TYPE_LONG_SIDE) & 0x01) {
			area_size[3] = (grip_zone->x_width >> 8) & 0xFF;
			area_size[4] = grip_zone->x_width & 0xFF;

		} else if ((grip_zone->grip_side >> TYPE_SHORT_SIDE) & 0x01) {
			area_size[3] = (grip_zone->y_width >> 8) & 0xFF;
			area_size[4] = grip_zone->y_width & 0xFF;
		}
	}

	ret = touch_i2c_write_block(chip_info->client, SEC_CMD_GRIP_AREA,
			sizeof(area_size), area_size);
	TPD_DETAIL("%s: cmd write is : 0x%02x, 0x%02x, 0x%02x, 0x%02x, 0x%02x, 0x%02x.\n",
			__func__, SEC_CMD_GRIP_AREA,
			area_size[0], area_size[1], area_size[2], area_size[3], area_size[4]);
	TPD_DETAIL("%s: %s area size is %s %s in fw : [%d, %d] [%d %d].\n", __func__,
			grip_zone->name, ret < 0 ? "failed" : "success", enable ? "change" : "remove",
			grip_zone->start_x, grip_zone->start_y,
			grip_zone->x_width, grip_zone->y_width);

	return ret;
}

static int long_size_condtion_zone_handle_func(
		struct chip_data_s6sy791 *chip_info,
		struct grip_zone_area *grip_zone, bool enable)
{
	int ret = 0;
	u8 area_size[5] = {LONG_PRESS_ZONE, 0, 0, 0xFF, 0xFF};
	u8 exit_thd[3] = {LONG_PRESS_ZONE, 0xFF, 0};

	if (!chip_info || !grip_zone || *chip_info->in_suspend) {
		return -1;
	}

	if (enable) {
		if ((grip_zone->grip_side >> TYPE_LONG_SIDE) & 0x01) {
			area_size[1] = (grip_zone->x_width >> 8) & 0xFF;
			area_size[2] = grip_zone->x_width & 0xFF;

		} else if ((grip_zone->grip_side >> TYPE_SHORT_SIDE) & 0x01) {
			area_size[1] = (grip_zone->y_width >> 8) & 0xFF;
			area_size[2] = grip_zone->y_width & 0xFF;
		}
	}

	ret = touch_i2c_write_block(chip_info->client, SEC_CMD_GRIP_AREA,
			sizeof(area_size), area_size);
	TPD_DETAIL("%s: cmd write is : 0x%02x, 0x%02x, 0x%02x, 0x%02x, 0x%02x, 0x%02x.\n",
			__func__, SEC_CMD_GRIP_AREA,
			area_size[0], area_size[1], area_size[2], area_size[3], area_size[4]);
	TPD_DETAIL("%s: %s area size is %s %s in fw : [%d, %d] [%d %d].\n", __func__,
			grip_zone->name, ret < 0 ? "failed" : "success", enable ? "change" : "remove",
			grip_zone->start_x, grip_zone->start_y,
			grip_zone->x_width, grip_zone->y_width);

	if (enable) {
		exit_thd[2] = grip_zone->exit_thd & 0xFF;
		ret = touch_i2c_write_block(chip_info->client, SEC_CMD_GRIP_PARA,
				sizeof(exit_thd), exit_thd);
		TPD_DETAIL("%s: cmd is : 0x%02x, 0x%02x, 0x%02x, 0x%02x.\n", __func__,
				SEC_CMD_GRIP_PARA, exit_thd[0], exit_thd[1], exit_thd[2]);
		TPD_DETAIL("%s: %s exit thd is %s change in fw : %d.\n", __func__,
				grip_zone->name, ret < 0 ? "failed" : "success", grip_zone->exit_thd);
	}

	return ret;
}

static int short_size_condtion_zone_handle_func(
		struct chip_data_s6sy791 *chip_info,
		struct grip_zone_area *grip_zone, bool enable)
{
	int ret = 0;
	u8 area_size[5] = {LONG_PRESS_ZONE, 0xFF, 0xFF, 0, 0};

	if (!chip_info || !grip_zone || *chip_info->in_suspend) {
		return -1;
	}

	if (enable) {
		if ((grip_zone->grip_side >> TYPE_LONG_SIDE) & 0x01) {
			area_size[3] = (grip_zone->x_width >> 8) & 0xFF;
			area_size[4] = grip_zone->x_width & 0xFF;

		} else if ((grip_zone->grip_side >> TYPE_SHORT_SIDE) & 0x01) {
			area_size[3] = (grip_zone->y_width >> 8) & 0xFF;
			area_size[4] = grip_zone->y_width & 0xFF;
		}
	}

	ret = touch_i2c_write_block(chip_info->client, SEC_CMD_GRIP_AREA,
			sizeof(area_size), area_size);
	TPD_DETAIL("%s: cmd write is : 0x%02x, 0x%02x, 0x%02x, 0x%02x, 0x%02x, 0x%02x.\n",
			__func__, SEC_CMD_GRIP_AREA,
			area_size[0], area_size[1], area_size[2], area_size[3], area_size[4]);
	TPD_DETAIL("%s: %s area size is %s %s in fw : [%d, %d] [%d %d].\n", __func__,
			grip_zone->name, ret < 0 ? "failed" : "success", enable ? "change" : "remove",
			grip_zone->start_x, grip_zone->start_y,
			grip_zone->x_width, grip_zone->y_width);

	return ret;
}

static int long_size_large_zone_handle_func(
		struct chip_data_s6sy791 *chip_info,
		struct grip_zone_area *grip_zone, bool enable)
{
	int ret = 0;
	u8 area_size[5] = {LARGE_TOUCH_REJECTION, 0, 0, 0xFF, 0xFF};

	if (!chip_info || !grip_zone || *chip_info->in_suspend) {
		return -1;
	}

	if (enable) {
		if ((grip_zone->grip_side >> TYPE_LONG_SIDE) & 0x01) {
			area_size[1] = (grip_zone->x_width >> 8) & 0xFF;
			area_size[2] = grip_zone->x_width & 0xFF;

		} else if ((grip_zone->grip_side >> TYPE_SHORT_SIDE) & 0x01) {
			area_size[1] = (grip_zone->y_width >> 8) & 0xFF;
			area_size[2] = grip_zone->y_width & 0xFF;
		}
	}

	ret = touch_i2c_write_block(chip_info->client, SEC_CMD_GRIP_AREA,
			sizeof(area_size), area_size);
	TPD_DETAIL("%s: cmd write is : 0x%02x, 0x%02x, 0x%02x, 0x%02x, 0x%02x, 0x%02x.\n",
			__func__, SEC_CMD_GRIP_AREA,
			area_size[0], area_size[1], area_size[2], area_size[3], area_size[4]);
	TPD_DETAIL("%s: %s area size is %s %s in fw : [%d, %d] [%d %d].\n", __func__,
			grip_zone->name, ret < 0 ? "failed" : "success", enable ? "change" : "remove",
			grip_zone->start_x, grip_zone->start_y,
			grip_zone->x_width, grip_zone->y_width);

	return ret;
}

static int short_size_large_zone_handle_func(
		struct chip_data_s6sy791 *chip_info,
		struct grip_zone_area *grip_zone, bool enable)
{
	int ret = 0;
	u8 area_size[5] = {LARGE_TOUCH_REJECTION, 0xFF, 0xFF, 0, 0};

	if (!chip_info || !grip_zone || *chip_info->in_suspend) {
		return -1;
	}

	if (enable) {
		if ((grip_zone->grip_side >> TYPE_LONG_SIDE) & 0x01) {
			area_size[3] = (grip_zone->x_width >> 8) & 0xFF;
			area_size[4] = grip_zone->x_width & 0xFF;

		} else if ((grip_zone->grip_side >> TYPE_SHORT_SIDE) & 0x01) {
			area_size[3] = (grip_zone->y_width >> 8) & 0xFF;
			area_size[4] = grip_zone->y_width & 0xFF;
		}
	}

	ret = touch_i2c_write_block(chip_info->client, SEC_CMD_GRIP_AREA,
			sizeof(area_size), area_size);
	TPD_DETAIL("%s: cmd write is : 0x%02x, 0x%02x, 0x%02x, 0x%02x, 0x%02x, 0x%02x.\n",
			__func__, SEC_CMD_GRIP_AREA,
			area_size[0], area_size[1], area_size[2], area_size[3], area_size[4]);
	TPD_DETAIL("%s: %s area size is %s %s in fw : [%d, %d] [%d %d].\n", __func__,
			grip_zone->name, ret < 0 ? "failed" : "success", enable ? "change" : "remove",
			grip_zone->start_x, grip_zone->start_y,
			grip_zone->x_width, grip_zone->y_width);

	return ret;
}

static int sec_set_fw_grip_area(void *chip_data,
		struct grip_zone_area *grip_zone, bool enable)
{
	int ret = 0, i = 0;
	struct chip_data_s6sy791 *chip_info = (struct chip_data_s6sy791 *)chip_data;

	if (!chip_info || !grip_zone || *chip_info->in_suspend) {
		return -1;
	}

	for (i = 0; i < ARRAY_SIZE(sec_grip); i++) {
		if (!strncmp(grip_zone->name, sec_grip[i].name, GRIP_TAG_SIZE)) {
			if (sec_grip[i].handle_func) {
				sec_grip[i].handle_func(chip_info, grip_zone, enable);
			}

			break;
		}
	}

	if (i == ARRAY_SIZE(sec_grip)) {
		TPD_DETAIL("%s: %s is not support in fw.\n", __func__, grip_zone->name);
		return 0;

	} else {
		TPD_INFO("%s: %s %s in fw : [%d, %d] [%d %d] %d %d %d.\n", __func__,
				grip_zone->name, enable ? "modify" : "remove", grip_zone->start_x,
				grip_zone->start_y,
				grip_zone->x_width, grip_zone->y_width, grip_zone->exit_thd,
				grip_zone->support_dir, grip_zone->grip_side);
	}

	return ret;
}

static int sec_set_no_handle_area(void *chip_data,
		struct kernel_grip_info *grip_info)
{
	int ret = 0;
	u8 edge_range[4] = {0}; /*edge sereen function setting, y1,y2,direction*/
	struct chip_data_s6sy791 *chip_info = (struct chip_data_s6sy791 *)chip_data;

	if (!chip_info || !grip_info || *chip_info->in_suspend) {
		return -1;
	}

	/* only portrait mode need set this area*/
	if (chip_info->touch_direction == 0) {
		/*
		   edge_range[0] = (grip_info->no_handle_y1 >> 4) & 0xFF;
		   edge_range[1] = (grip_info->no_handle_y1 & 0x0F) << 4 | ((grip_info->no_handle_y2 >> 8) & 0x0F);
		   edge_range[2] = grip_info->no_handle_y2 & 0xFF;
		   if (!grip_info->no_handle_dir) {
		   edge_range[3] = 0x01;
		   } else {
		   edge_range[3] = 0x00;
		   }
		 */
	}

	ret = touch_i2c_write_block(chip_info->client, SEC_CMD_EDGE_SCREEN,
			sizeof(edge_range), edge_range);
	TPD_DETAIL("%s: cmd write is : 0x%02x, 0x%02x, 0x%02x, 0x%02x, 0x%02x.\n",
			__func__, SEC_CMD_EDGE_SCREEN,
			edge_range[0], edge_range[1], edge_range[2], edge_range[3]);
	TPD_DETAIL("%s: No handle area is %s change in fw : [%d, %d, %d].\n", __func__,
			ret < 0 ? "failed" : "success",
			grip_info->no_handle_dir, grip_info->no_handle_y1, grip_info->no_handle_y2);

	return ret;
}

static int sec_set_condition_frame_limit(void *chip_data, int frame_limit)
{
	int ret = 0;
	u8 press_time[3] = {LONG_PRESS_ZONE, 0, 0xFF};
	struct chip_data_s6sy791 *chip_info = (struct chip_data_s6sy791 *)chip_data;

	if (!chip_info || *chip_info->in_suspend) {
		return -1;
	}

	press_time[1] = frame_limit;

	ret = touch_i2c_write_block(chip_info->client, SEC_CMD_GRIP_PARA,
			sizeof(press_time), press_time);
	TPD_DETAIL("%s: cmd write is : 0x%02x, 0x%02x, 0x%02x, 0x%02x.\n", __func__,
			SEC_CMD_GRIP_PARA,
			press_time[0], press_time[1], press_time[2]);
	TPD_DETAIL("%s: Condition frame limit is %s change in fw : frame_limit = %d.\n",
			__func__, ret < 0 ? "failed" : "success", frame_limit);

	return ret;
}

static int sec_set_large_frame_limit(void *chip_data, int frame_limit)
{
	int ret = 0;
	u8 press_time[3] = {LARGE_TOUCH_REJECTION, 0, 0xFF};
	struct chip_data_s6sy791 *chip_info = (struct chip_data_s6sy791 *)chip_data;

	if (!chip_info || *chip_info->in_suspend) {
		return -1;
	}

	press_time[1] = frame_limit;

	ret = touch_i2c_write_block(chip_info->client, SEC_CMD_GRIP_PARA,
			sizeof(press_time), press_time);
	TPD_DETAIL("%s: cmd write is : 0x%02x, 0x%02x, 0x%02x, 0x%02x.\n", __func__,
			SEC_CMD_GRIP_PARA,
			press_time[0], press_time[1], press_time[2]);
	TPD_DETAIL("%s: large frame limit is %s change in fw : frame_limit = %d.\n",
			__func__, ret < 0 ? "failed" : "success", frame_limit);

	return ret;
}

static int sec_set_large_corner_frame_limit(void *chip_data, int frame_limit)
{
	int ret = 0;
	u8 press_time[3] = {CORNER_LONG_PRESS_ZONE, 0, 0xFF};
	struct chip_data_s6sy791 *chip_info = (struct chip_data_s6sy791 *)chip_data;

	if (!chip_info || *chip_info->in_suspend) {
		return -1;
	}

	press_time[1] = frame_limit;

	ret = touch_i2c_write_block(chip_info->client, SEC_CMD_GRIP_PARA,
			sizeof(press_time), press_time);
	TPD_DETAIL("%s: cmd write is : 0x%02x, 0x%02x, 0x%02x, 0x%02x.\n", __func__,
			SEC_CMD_GRIP_PARA,
			press_time[0], press_time[1], press_time[2]);
	TPD_DETAIL("%s: large corner frame limit is %s change in fw : frame_limit = %d.\n",
			__func__, ret < 0 ? "failed" : "success", frame_limit);

	return ret;
}

static int sec_set_large_thd(void *chip_data, int large_thd)
{
	int ret = 0;
	u8 touch_size[3] = {LARGE_TOUCH_REJECTION, 0xFF, 0};
	struct chip_data_s6sy791 *chip_info = (struct chip_data_s6sy791 *)chip_data;

	if (!chip_info || *chip_info->in_suspend) {
		return -1;
	}

	touch_size[2] = large_thd;

	ret = touch_i2c_write_block(chip_info->client, SEC_CMD_GRIP_PARA,
			sizeof(touch_size), touch_size);
	TPD_DETAIL("%s: cmd write is : 0x%02x, 0x%02x, 0x%02x, 0x%02x.\n", __func__,
			SEC_CMD_GRIP_PARA,
			touch_size[0], touch_size[1], touch_size[2]);
	TPD_DETAIL("%s: large ver thd is %s change in fw : large_thd = %d.\n", __func__,
			ret < 0 ? "failed" : "success", large_thd);

	return ret;
}

static void sec_set_grip_touch_direction(void *chip_data, uint8_t dir)
{
	int ret = -1;
	u8 buf = 0x00; /*direction enable, landscape grip area*/
	struct chip_data_s6sy791 *chip_info = (struct chip_data_s6sy791 *)chip_data;

	if (!chip_info) {
		return;
	}

	chip_info->touch_direction = dir;

	if (*chip_info->in_suspend) {
		TPD_INFO("%s: set touch_direction in suspend: %d!\n", __func__,
				chip_info->touch_direction);
		return;
	}

	buf = dir;
	ret = touch_i2c_write_byte(chip_info->client, SEC_CMD_GRIP_DIRECTION, buf);

	/*disable wet mode while changing to horizontal*/
	ret |= touch_i2c_write_byte(chip_info->client, SEC_CMD_WET_SWITCH,
			!!chip_info->touch_direction);

	TPD_INFO("%s: set touch_direction: %d %s!\n", __func__,
			chip_info->touch_direction, ret < 0 ? "failed" : "success");
}

static struct fw_grip_operations sec_fw_grip_op = {
	.set_fw_grip_area             = sec_set_fw_grip_area,
	.set_touch_direction          = sec_set_grip_touch_direction,
	.set_no_handle_area           = sec_set_no_handle_area,
	.set_condition_frame_limit    = sec_set_condition_frame_limit,
	.set_large_frame_limit        = sec_set_large_frame_limit,
	.set_large_corner_frame_limit = sec_set_large_corner_frame_limit,
	.set_large_ver_thd            = sec_set_large_thd,
};
/*********** end of kernel grip callbacks*************************/

static struct sec_proc_operations sec_proc_ops = {
	.calibrate          = sec_calibrate,
	.verify_calibration = sec_verify_calibration,
	.get_cal_status     = sec_get_cal_status,
};

#ifdef CONFIG_OPLUS_TP_APK

static void sec_apk_game_set(void *chip_data, bool on_off)
{
	struct chip_data_s6sy791 *chip_info;
	chip_info = (struct chip_data_s6sy791 *)chip_data;
	sec_mode_switch(chip_data, MODE_GAME, on_off);
	chip_info->lock_point_status = on_off;
}

static bool sec_apk_game_get(void *chip_data)
{
	struct chip_data_s6sy791 *chip_info;
	chip_info = (struct chip_data_s6sy791 *)chip_data;
	return chip_info->lock_point_status;
}

static void sec_apk_gesture_debug(void *chip_data, bool on_off)
{
	struct chip_data_s6sy791 *chip_info;
	chip_info = (struct chip_data_s6sy791 *)chip_data;

	/*get_gesture_fail_reason(on_off);*/
	if (on_off) {
		if (chip_info->gesture_buf == NULL) {
			chip_info->gesture_buf = tp_devm_kzalloc(&chip_info->client->dev, 4096,
					GFP_KERNEL);
		}

		if (chip_info->gesture_buf == NULL) {
			chip_info->debug_gesture_sta = false;
			return;
		}
	}

	chip_info->debug_gesture_sta = on_off;
}

static bool  sec_apk_gesture_get(void *chip_data)
{
	struct chip_data_s6sy791 *chip_info;
	chip_info = (struct chip_data_s6sy791 *)chip_data;
	return chip_info->debug_gesture_sta;
}

static int  sec_apk_gesture_info(void *chip_data, char *buf, int len)
{
	int ret = 0;
	int i;
	int j;
	int num;
	int delta_index = 0;
	int count = 0;
	struct chip_data_s6sy791 *chip_info;

	chip_info = (struct chip_data_s6sy791 *)chip_data;

	if (len < 2) {
		return 0;
	}

	buf[0] = 255;

	if (chip_info->debug_gesture_type != 0) {
		buf[0] = chip_info->debug_gesture_type;
	}

	num = chip_info->geture_points_count;

	ret = 2;

	buf[1] = 0;

	if (num > 127) {
		delta_index = (num + 1) / 128;
	}

	/*print all data*/
	for (i = 0; i < 3; i++) {
		int temp;
		temp = delta_index;

		for (j = 0; j < num; j++) {
			if (chip_info->gesture_buf[j * 4] == i) {
				int x;
				int y;

				x = (chip_info->gesture_buf[j * 4 + 1] << 4) | (chip_info->gesture_buf[j * 4 +
						3] >> 4);

				y = (chip_info->gesture_buf[j * 4 + 2] << 4) | (chip_info->gesture_buf[j * 4 +
						3] & 0x0F);


				/*TPD_INFO("nova_apk_gesture_info:gesture x is %d,y is %d.\n", x, y);*/

				if (len < i * 4 + 2) {
					break;
				}

				buf[count * 4 + 2] = x & 0xFF;
				buf[count * 4 + 3] = (x >> 8) & 0xFF;
				buf[count * 4 + 4] = y & 0xFF;
				buf[count * 4 + 5] = (y >> 8) & 0xFF;
				temp++;

				if (temp > delta_index) {
					temp = 0;
					count++;
					ret += 4;
				}
			}
		}

		if (temp != 0) {
			count++;
			ret += 4;
		}
	}

	buf[1] = count;

	return ret;
}


static void sec_apk_earphone_set(void *chip_data, bool on_off)
{
	struct chip_data_s6sy791 *chip_info;
	chip_info = (struct chip_data_s6sy791 *)chip_data;
	sec_mode_switch(chip_data, MODE_HEADSET, on_off);
	chip_info->earphone_sta = on_off;
}

static bool sec_apk_earphone_get(void *chip_data)
{
	struct chip_data_s6sy791 *chip_info;
	chip_info = (struct chip_data_s6sy791 *)chip_data;
	return chip_info->earphone_sta;
}

static void sec_apk_charger_set(void *chip_data, bool on_off)
{
	struct chip_data_s6sy791 *chip_info;
	chip_info = (struct chip_data_s6sy791 *)chip_data;
	sec_mode_switch(chip_data, MODE_CHARGE, on_off);
	chip_info->plug_status = on_off;
}

static bool sec_apk_charger_get(void *chip_data)
{
	struct chip_data_s6sy791 *chip_info;
	chip_info = (struct chip_data_s6sy791 *)chip_data;

	return chip_info->plug_status;
}

static void sec_apk_water_set(void *chip_data, int type)
{
	struct chip_data_s6sy791 *chip_info;
	chip_info = (struct chip_data_s6sy791 *)chip_data;

	/*ilitek_mode_switch(chip_data, MODE_CHARGE, on_off);*/
	if (type > 0) {
		touch_i2c_write_byte(chip_info->client, SEC_CMD_WET_SWITCH, 3);

	} else {
		touch_i2c_write_byte(chip_info->client, SEC_CMD_WET_SWITCH, 0);
	}

	/*chip_info->water_sta = type;*/
}

static int sec_apk_water_get(void *chip_data)
{
	struct chip_data_s6sy791 *chip_info;
	int ret = -1;
	chip_info = (struct chip_data_s6sy791 *)chip_data;
	ret = touch_i2c_read_byte(chip_info->client, SEC_CMD_WET_SWITCH);

	if (ret == 3) {
		return 1;
	}

	return 0;
}


static int  sec_apk_tp_info_get(void *chip_data, char *buf, int len)
{
	int ret;
	struct chip_data_s6sy791 *chip_info;
	unsigned char data[5];
	int fw_ver;
	chip_info = (struct chip_data_s6sy791 *)chip_data;
	memset(data, 0, 5);
	touch_i2c_read_block(chip_info->client, SEC_READ_IMG_VERSION, 4, data);
	fw_ver = (data[0] << 24) | (data[1] << 16) | (data[2] << 8) | data[3];
	ret = snprintf(buf, len, "IC:S6SY%03X\nFW_VER:0x%02X\nCH:%dX%d\n",
			0x791,
			fw_ver,
			chip_info->hw_res->tx_num,
			chip_info->hw_res->rx_num);

	if (ret > len) {
		ret = len;
	}

	return ret;
}

static void sec_init_oplus_apk_op(struct touchpanel_data *ts)
{
	ts->apk_op = tp_devm_kzalloc(&ts->client->dev, sizeof(APK_OPERATION),
			GFP_KERNEL);

	if (ts->apk_op) {
		ts->apk_op->apk_game_set = sec_apk_game_set;
		ts->apk_op->apk_game_get = sec_apk_game_get;
		/*ts->apk_op->apk_debug_set = sec_apk_debug_set;*/
		/*ts->apk_op->apk_debug_get = sec_apk_debug_get;*/
		/*apk_op->apk_proximity_set = sec_apk_proximity_set;*/
		/*apk_op->apk_proximity_dis = sec_apk_proximity_dis;*/
		/*ts->apk_op->apk_noise_set = sec_apk_noise_set;*/
		/*ts->apk_op->apk_noise_get = sec_apk_noise_get;*/
		ts->apk_op->apk_gesture_debug = sec_apk_gesture_debug;
		ts->apk_op->apk_gesture_get = sec_apk_gesture_get;
		ts->apk_op->apk_gesture_info = sec_apk_gesture_info;
		ts->apk_op->apk_earphone_set = sec_apk_earphone_set;
		ts->apk_op->apk_earphone_get = sec_apk_earphone_get;
		ts->apk_op->apk_charger_set = sec_apk_charger_set;
		ts->apk_op->apk_charger_get = sec_apk_charger_get;
		ts->apk_op->apk_tp_info_get = sec_apk_tp_info_get;
		ts->apk_op->apk_water_set = sec_apk_water_set;
		ts->apk_op->apk_water_get = sec_apk_water_get;
		/*apk_op->apk_data_type_set = sec_apk_data_type_set;*/
		/*apk_op->apk_rawdata_get = sec_apk_rawdata_get;*/
		/*apk_op->apk_diffdata_get = sec_apk_diffdata_get;*/
		/*apk_op->apk_basedata_get = sec_apk_basedata_get;*/
		/*ts->apk_op->apk_backdata_get = sec_apk_backdata_get;*/
		/*apk_op->apk_debug_info = sec_apk_debug_info;*/

	} else {
		TPD_INFO("Can not devm_kzalloc apk op.\n");
	}
}
#endif /* end of CONFIG_OPLUS_TP_APK*/




/*********** Start of I2C Driver and Implementation of it's callbacks*************************/
static int sec_tp_probe(struct i2c_client *client,
		const struct i2c_device_id *id)
{
	struct chip_data_s6sy791 *chip_info = NULL;
	struct touchpanel_data *ts = NULL;
	u64 time_counter = 0;
	int ret = -1;

	TPD_INFO("%s  is called\n", __func__);

	reset_healthinfo_time_counter(&time_counter);

	/* 1. alloc chip info */
	chip_info = kzalloc(sizeof(struct chip_data_s6sy791), GFP_KERNEL);

	if (chip_info == NULL) {
		TPD_INFO("chip info kzalloc error\n");
		ret = -ENOMEM;
		return ret;
	}

	/* 2. Alloc common ts */
	ts = common_touch_data_alloc();

	if (ts == NULL) {
		TPD_INFO("ts kzalloc error\n");
		goto ts_malloc_failed;
	}

	memset(ts, 0, sizeof(*ts));

	/* 3. bind client and dev for easy operate */
	chip_info->client = client;
	ts->debug_info_ops = &debug_info_proc_ops;
	ts->client = client;
	ts->irq = client->irq;
	i2c_set_clientdata(client, ts);
	ts->dev = &client->dev;
	ts->chip_data = chip_info;
	chip_info->hw_res = &ts->hw_res;
	chip_info->in_suspend = &ts->is_suspended;
	chip_info->cal_needed = false;
	chip_info->touch_direction = VERTICAL_SCREEN;

	/* 4. file_operations callbacks binding */
	ts->ts_ops = &sec_ops;
	ts->engineer_ops = &sec_engineer_test_ops;
	ts->com_test_data.chip_test_ops = &sec_test_ops;

	/* 5. register common touch device*/
	ret = register_common_touch_device(ts);

	if (ret < 0) {
		goto err_register_driver;
	}

	chip_info->irq_requested = true;
	ts->tp_suspend_order = TP_LCD_SUSPEND;
	chip_info->monitor_data = &ts->monitor_data;

	/*get ts tp_index to chip info*/
	chip_info->tp_index = ts->tp_index;

	/* 6. create debug interface*/
	sec_raw_device_init(ts);
	sec_create_proc(ts, &sec_proc_ops);

#ifdef CONFIG_OPLUS_TP_APK
	sec_init_oplus_apk_op(ts);
#endif /* end of CONFIG_OPLUS_TP_APK*/

	/* 7. kernel grip interface init*/
	if (ts->grip_info) {
		if (ts->grip_info->grip_handle_in_fw) {
			ts->grip_info->fw_ops = &sec_fw_grip_op;
		}
	}

	if (ts->health_monitor_support) {
		tp_healthinfo_report(&ts->monitor_data, HEALTH_PROBE, &time_counter);
	}

	TPD_INFO("%s, probe normal end\n", __func__);

	/* update firmware*/
	if (ts->firmware_in_dts) {
		sec_fw_update(chip_info, ts->firmware_in_dts, false);
	}

	return 0;

err_register_driver:
	i2c_set_clientdata(client, NULL);
	common_touch_data_free(ts);
	ts = NULL;

ts_malloc_failed:
	kfree(chip_info);
	chip_info = NULL;
	/* ret = -1; */

	TPD_INFO("%s, probe error\n", __func__);
	return ret;
}

static void sec_tp_shutdown(struct i2c_client *client)
{
	struct touchpanel_data *ts = i2c_get_clientdata(client);

	TPD_INFO("%s is called\n", __func__);
	tp_shutdown(ts);
}

static int sec_tp_remove(struct i2c_client *client)
{
	struct touchpanel_data *ts = i2c_get_clientdata(client);

	TPD_INFO("%s is called\n", __func__);

	if (ts) {
		sec_remove_proc(ts);
		sec_raw_device_release(ts);
		common_touch_data_free(ts);
		ts = NULL;
	}

	return 0;
}

static int sec_i2c_suspend(struct device *dev)
{
	struct touchpanel_data *ts = dev_get_drvdata(dev);

	TPD_INFO("%s: is called\n", __func__);
	tp_pm_suspend(ts);

	return 0;
}

static int sec_i2c_resume(struct device *dev)
{
	struct touchpanel_data *ts = dev_get_drvdata(dev);

	TPD_INFO("%s is called\n", __func__);
	tp_pm_resume(ts);

	return 0;
}

static const struct i2c_device_id tp_id[] = {
	{TPD_DEVICE, 0},
	{},
};

static struct of_device_id tp_match_table[] = {
	{ .compatible = TPD_DEVICE, },
	{ },
};

static const struct dev_pm_ops tp_pm_ops = {
	.suspend = sec_i2c_suspend,
	.resume = sec_i2c_resume,
};

static struct i2c_driver tp_i2c_driver = {
	.probe    = sec_tp_probe,
	.shutdown = sec_tp_shutdown,
	.remove   = sec_tp_remove,
	.id_table = tp_id,
	.driver   = {
		.name           = TPD_DEVICE,
		.owner          = THIS_MODULE,
		.of_match_table = tp_match_table,
		.pm             = &tp_pm_ops,
	},
};
/******************* End of I2C Driver and It's dev_pm_ops***********************/

/***********************Start of module init and exit****************************/

int __init tp_driver_init_y791(void)
{
	TPD_INFO("%s is called\n", __func__);

	if (!tp_judge_ic_match(TPD_DEVICE)) {
		return -1;
	}

	if (i2c_add_driver(&tp_i2c_driver) != 0) {
		TPD_INFO("unable to add i2c driver.\n");
		return -1;
	}

	return 0;
}

/* should never be called */
void __exit tp_driver_exit_y791(void)
{
	TPD_INFO("tp_driver_exit called!\n");
	i2c_del_driver(&tp_i2c_driver);
	return;
}

#ifdef CONFIG_TOUCHPANEL_LATE_INIT
late_initcall(tp_driver_init_y791);
#else
module_init(tp_driver_init_y791);
#endif
module_exit(tp_driver_exit_y791);

MODULE_DESCRIPTION("Touchscreen s6sy791 Driver");
MODULE_LICENSE("GPL");
