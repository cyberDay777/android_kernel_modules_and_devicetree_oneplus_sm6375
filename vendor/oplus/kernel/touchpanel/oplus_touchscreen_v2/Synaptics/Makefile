#
# Makefile for the touchscreen drivers.
#

# Each configuration option enables a list of files.
obj-$(CONFIG_TOUCHPANEL_SYNAPTICS_S3706) += S3706/
obj-$(CONFIG_TOUCHPANEL_SYNAPTICS_TCM_ONCELL) += Syna_tcm_oncell/
obj-$(CONFIG_TOUCHPANEL_SYNAPTICS_TD4377_NOFLASH) += TD4377_noflash/

oplus_bsp_tp_syna_comnon-y += synaptics_touch_panel_remote.o
oplus_bsp_tp_syna_comnon-y += synaptics_common.o
obj-$(CONFIG_TOUCHPANEL_SYNAPTICS) += oplus_bsp_tp_syna_comnon.o
obj-$(CONFIG_TOUCHPANEL_SYNAPTICS_TCM_S3910) += Syna_tcm_S3910/
#endif
