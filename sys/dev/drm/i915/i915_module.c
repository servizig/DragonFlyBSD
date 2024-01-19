/* Public domain. */

#include <linux/types.h>
#include <linux/ioport.h>
#include <linux/pci.h>
#include <drm/i915_drm.h>
#include "i915_drv.h"

struct linux_resource intel_graphics_stolen_res = DEFINE_RES_MEM(0, 0);
