/* Public domain. */

#if !defined(_AMDGPU_DM_TRACE_H) || defined(TRACE_HEADER_MULTI_READ)
#define _AMDGPU_DM_TRACE_H_

#define trace_amdgpu_dc_rreg(read_count, address, value)
#define trace_amdgpu_dc_wreg(write_count, address, value)
#define trace_amdgpu_dc_performance(read_count,\
		write_count, last_entry_read,\
		last_entry_write, func, line)

#endif /* _AMDGPU_DM_TRACE_H_ */
