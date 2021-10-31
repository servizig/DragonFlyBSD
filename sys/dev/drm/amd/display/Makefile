.PATH:	${.CURDIR}/dc \
	${.CURDIR}/dc/basics \
	${.CURDIR}/dc/bios \
	${.CURDIR}/dc/bios/dce80 \
	${.CURDIR}/dc/bios/dce110 \
	${.CURDIR}/dc/bios/dce112 \
	${.CURDIR}/dc/calcs \
	${.CURDIR}/dc/core \
	${.CURDIR}/dc/dce \
	${.CURDIR}/dc/gpio \
	${.CURDIR}/dc/gpio/dce110 \
	${.CURDIR}/dc/gpio/dce120 \
	${.CURDIR}/dc/gpio/dce80 \
	${.CURDIR}/dc/gpio/dcn10 \
	${.CURDIR}/dc/gpio/diagnostics \
	${.CURDIR}/dc/i2caux \
	${.CURDIR}/dc/i2caux/dce100 \
	${.CURDIR}/dc/i2caux/dce110 \
	${.CURDIR}/dc/i2caux/dce112 \
	${.CURDIR}/dc/i2caux/dce120 \
	${.CURDIR}/dc/i2caux/dce80 \
	${.CURDIR}/dc/i2caux/dcn10 \
	${.CURDIR}/dc/i2caux/diagnostics \
	${.CURDIR}/dc/irq \
	${.CURDIR}/dc/irq/dce110 \
	${.CURDIR}/dc/irq/dce120 \
	${.CURDIR}/dc/irq/dce80 \
	${.CURDIR}/dc/irq/dcn10 \
	${.CURDIR}/dc/virtual \
	${.CURDIR}/dc/dcn10 \
	${.CURDIR}/dc/dml \
	${.CURDIR}/dc/dce120 \
	${.CURDIR}/dc/dce112 \
	${.CURDIR}/dc/dce110 \
	${.CURDIR}/dc/dce100 \
	${.CURDIR}/dc/dce80 \
	${.CURDIR}/modules/freesync \
	${.CURDIR}/modules/color

# amdgpu_dm
SRC+= amdgpu_dm.c amdgpu_dm_irq.c amdgpu_dm_mst_types.c amdgpu_dm_color.c
# ifneq ($(CONFIG_DRM_AMD_DC),)
SRC+= amdgpu_dm_services.c amdgpu_dm_helpers.c amdgpu_dm_pp_smu.c

# dc
# dc/basics
SRCS+= conversion.c fixpt31_32.c \
	log_helpers.c vector.c

# dc/bios
SRCS+= bios_parser.c bios_parser_interface.c  bios_parser_helper.c \
	command_table.c command_table_helper.c bios_parser_common.c
SRCS+= command_table2.c command_table_helper2.c bios_parser2.c
# DCE 8x
# All DCE8.x are derived from DCE8.0, so 8.0 MUST be defined if ANY of
# DCE8.x is compiled.
SRCS+= command_table_helper_dce80.c

# DCE 11x
SRCS+= command_table_helper_dce110.c
SRCS+= command_table_helper_dce112.c
SRCS+= command_table_helper2_dce112.c

# dc/calcs
SRCS+= dce_calcs.c bw_fixed.c custom_float.c

# ifdef CONFIG_DRM_AMD_DC_DCN1_0
SRCS+= dcn_calcs.c dcn_calc_math.c dcn_calc_auto.c

# dc/dce
SRCS+= dce_audio.c dce_stream_encoder.c dce_link_encoder.c dce_hwseq.c \
	dce_mem_input.c dce_clock_source.c dce_scl_filters.c dce_transform.c \
dce_clocks.c dce_opp.c dce_dmcu.c dce_abm.c dce_ipp.c dce_aux.c

# dc/gpio
SRCS+= gpio_base.c gpio_service.c hw_factory.c \
       hw_gpio.c hw_hpd.c hw_ddc.c hw_translate.c

# DCE 8x
# all DCE8.x are derived from DCE8.0
SRCS+= hw_translate_dce80.c hw_factory_dce80.c

# DCE 11x
SRCS+= hw_translate_dce110.c hw_factory_dce110.c

# DCE 12x
SRCS+= hw_translate_dce120.c hw_factory_dce120.c

# DCN 1x
# ifdef CONFIG_DRM_AMD_DC_DCN1_0
SRCS+= hw_translate_dcn10.c hw_factory_dcn10.c

# Diagnostics on FPGA
SRCS+= hw_translate_diag.c hw_factory_diag.c

# dc/i2caux
SRCS+= aux_engine.c engine_base.c i2caux.c i2c_engine.c \
	 i2c_generic_hw_engine.c i2c_hw_engine.c i2c_sw_engine.c
# DCE 8x family
SRCS+= i2caux_dce80.c i2c_hw_engine_dce80.c \
	i2c_sw_engine_dce80.c

# DCE 100 family
SRCS+= i2caux_dce100.c

# DCE 110 family
SRCS+= i2caux_dce110.c i2c_sw_engine_dce110.c i2c_hw_engine_dce110.c \
	aux_engine_dce110.c

# DCE 112 family
SRCS+= i2caux_dce112.c

# DCN 1.0 family
# ifdef CONFIG_DRM_AMD_DC_DCN1_0
SRCS+= i2caux_dcn10.c

# DCE 120 family
SRCS+= i2caux_dce120.c

SRCS+= i2caux_diag.c

# dc/irq
SRCS+= irq_service.c

# DCE 8x
SRCS+= irq_service_dce80.c

# DCE 11x
SRCS+= irq_service_dce110.c

# DCE 12x
SRCS+= irq_service_dce120.c

# DCN 1x
# ifdef CONFIG_DRM_AMD_DC_DCN1_0
SRCS+= irq_service_dcn10.c

# dc/virtual
SRCS+= virtual_link_encoder.c virtual_stream_encoder.c

# dc/dcn10
SRCS+= dcn10_resource.c dcn10_ipp.c dcn10_hw_sequencer.c \
	dcn10_dpp.c dcn10_opp.c dcn10_optc.c \
	dcn10_hubp.c dcn10_mpc.c \
	dcn10_dpp_dscl.c dcn10_dpp_cm.c dcn10_cm_common.c \
	dcn10_hubbub.c dcn10_stream_encoder.c dcn10_link_encoder.c

# dc/dml
SRCS+= display_mode_lib.c display_rq_dlg_helpers.c dml1_display_rq_dlg_calc.c \
	dml_common_defs.c

# dc/dce120
SRCS+= dce120_resource.c dce120_timing_generator.c \
	dce120_hw_sequencer.c

# dc/dce112
SRCS+= dce112_compressor.c dce112_hw_sequencer.c \
	dce112_resource.c

# dc/dce110
SRCS+= dce110_timing_generator.c \
	dce110_compressor.c dce110_hw_sequencer.c dce110_resource.c \
	dce110_opp_regamma_v.c dce110_opp_csc_v.c dce110_timing_generator_v.c \
	dce110_mem_input_v.c dce110_opp_v.c dce110_transform_v.c

# dc/dce100
SRCS+= dce100_resource.c dce100_hw_sequencer.c

# dc/dce80
SRCS+= dce80_timing_generator.c dce80_hw_sequencer.c \
	dce80_resource.c

SRCS+= dc.c dc_link.c dc_resource.c dc_hw_sequencer.c dc_sink.c \
	dc_surface.c dc_link_hwss.c dc_link_dp.c dc_link_ddc.c dc_debug.c dc_stream.c
SRCS+= dc_helper.c

# modules/freesync
SRCS+= freesync.c

# modules/color
SRCS+= color_gamma.c

SRCS+= \
	opt_ddb.h 	\
	opt_acpi.h	\
	opt_drm.h 	\
	acpi_if.h	\
	bus_if.h	\
	device_if.h	\
	pci_if.h

# From linux
#TODO: remove when Timing Sync feature is complete
KCFLAGS+= -DBUILD_FEATURE_TIMING_SYNC=0

KCFLAGS+= -I${SYSDIR}/dev/drm/include
KCFLAGS+= -I${SYSDIR}/dev/drm/include/drm
KCFLAGS+= -I${SYSDIR}/dev/drm/include/uapi
KCFLAGS+= -I${SYSDIR}/dev/drm/include/uapi/drm
KCFLAGS+= -I${SYSDIR}/contrib/dev/acpica/source/include
KCFLAGS+= -I${SYSDIR}/dev/drm/amd/amdgpu
KCFLAGS+= -I${SYSDIR}/dev/drm/amd/include
KCFLAGS+= -I${SYSDIR}/dev/drm/amd/include/asic_reg

KCFLAGS+= -I${SYSDIR}/dev/drm/amd/display
KCFLAGS+= -I${SYSDIR}/dev/drm/amd/display/include
KCFLAGS+= -I${SYSDIR}/dev/drm/amd/display/dc
KCFLAGS+= -I${SYSDIR}/dev/drm/amd/display/dc/inc
KCFLAGS+= -I${SYSDIR}/dev/drm/amd/display/dc/inc/hw
KCFLAGS+= -I${SYSDIR}/dev/drm/amd/display/modules/inc
KCFLAGS+= -I${SYSDIR}/dev/drm/amd/display/modules/freesync
KCFLAGS+= -I${SYSDIR}/dev/drm/amd/display/modules/color
KCFLAGS+= -I${SYSDIR}/dev/drm/amd/display/amdgpu_dm

KCFLAGS+= -include ${SYSDIR}/dev/drm/kconfig.h

.include <bsd.kmod.mk>
