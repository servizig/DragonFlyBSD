/*-
 * SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2015-2021 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 * Copyright (C) 2019-2021 Matt Dunwoodie <ncon@noconroy.net>
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject
 * to the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 * IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
 * CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
 * TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
 * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

#define T_MESSAGE_LEN 64
#define T_FAILED_ITER(test) do {				\
	kprintf("%s %s: FAIL, iter: %d\n", __func__, test, i);	\
	goto cleanup;						\
} while (0)
#define T_FAILED(test) do {				\
	kprintf("%s %s: FAIL\n", __func__, test);	\
	goto cleanup;					\
} while (0)
#define T_PASSED kprintf("%s: pass\n", __func__)

static const struct expected_results {
	int		result;
	uint64_t	sleep_time; /* nanoseconds */
} rl_expected[] = {
	/* [0 ... INITIATIONS_BURSTABLE-1] entries are implied zero. */
	[INITIATIONS_BURSTABLE] = { ECONNREFUSED, 0 },
	[INITIATIONS_BURSTABLE + 1] = { 0, INITIATION_COST },
	[INITIATIONS_BURSTABLE + 2] = { ECONNREFUSED, 0 },
	[INITIATIONS_BURSTABLE + 3] = { 0, INITIATION_COST * 2 },
	[INITIATIONS_BURSTABLE + 4] = { 0, 0 },
	[INITIATIONS_BURSTABLE + 5] = { ECONNREFUSED, 0 },
};

static struct ratelimit rl_test;

static bool
cookie_ratelimit_timings_test(void)
{
	struct sockaddr_in sin = { .sin_family = AF_INET };
#ifdef INET6
	struct sockaddr_in6 sin6 = { .sin6_family = AF_INET6 };
#endif
	uint64_t t;
	int i;
	bool ret = false;

	ratelimit_init(&rl_test);

	for (i = 0; i < nitems(rl_expected); i++) {
		if ((t = rl_expected[i].sleep_time) != 0) {
			tsleep(&rl_test, 0, "rl_test",
			       (int)(t * hz / NSEC_PER_SEC));
		}

		/*
		 * The first v4 ratelimit_allow is against a constant address,
		 * and should be indifferent to the port.
		 */
		sin.sin_addr.s_addr = 0x01020304;
		sin.sin_port = karc4random();

		if (ratelimit_allow(&rl_test, sintosa(&sin))
		    != rl_expected[i].result)
			T_FAILED_ITER("malicious v4");

		/*
		 * The second ratelimit_allow is to test that an arbitrary
		 * address is still allowed.
		 */
		sin.sin_addr.s_addr += i + 1;
		sin.sin_port = karc4random();

		if (ratelimit_allow(&rl_test, sintosa(&sin)) != 0)
			T_FAILED_ITER("non-malicious v4");

#ifdef INET6
		/*
		 * The first v6 ratelimit_allow is against a constant address,
		 * and should be indifferent to the port.  We also mutate the
		 * lower 64 bits of the address as we want to ensure ratelimit
		 * occurs against the higher 64 bits (/64 network).
		 */
		sin6.sin6_addr.s6_addr32[0] = 0x01020304;
		sin6.sin6_addr.s6_addr32[1] = 0x05060708;
		sin6.sin6_addr.s6_addr32[2] = i;
		sin6.sin6_addr.s6_addr32[3] = i;
		sin6.sin6_port = karc4random();

		if (ratelimit_allow(&rl_test, sin6tosa(&sin6))
		    != rl_expected[i].result)
			T_FAILED_ITER("malicious v6");

		/*
		 * Again, test that an address different to above is still
		 * allowed.
		 */
		sin6.sin6_addr.s6_addr32[0] += i + 1;
		sin6.sin6_port = karc4random();

		if (ratelimit_allow(&rl_test, sintosa(&sin)) != 0)
			T_FAILED_ITER("non-malicious v6");
#endif
	}
	T_PASSED;
	ret = true;

cleanup:
	ratelimit_deinit(&rl_test);
	return (ret);
}

static bool
cookie_ratelimit_capacity_test(void)
{
	struct sockaddr_in sin;
	int i;
	bool ret = false;

	ratelimit_init(&rl_test);

	sin.sin_family = AF_INET;
	sin.sin_port = 1234;

	/*
	 * Test that the ratelimiter has an upper bound on the number of
	 * addresses to be limited.
	 */
	for (i = 0; i <= RATELIMIT_SIZE_MAX; i++) {
		sin.sin_addr.s_addr = i;
		if (i == RATELIMIT_SIZE_MAX) {
			if (ratelimit_allow(&rl_test, sintosa(&sin))
			    != ECONNREFUSED)
				T_FAILED_ITER("reject");
		} else {
			if (ratelimit_allow(&rl_test, sintosa(&sin)) != 0)
				T_FAILED_ITER("allow");
		}
	}
	T_PASSED;
	ret = true;

cleanup:
	ratelimit_deinit(&rl_test);
	return (ret);
}

static bool
cookie_ratelimit_gc_test(void)
{
	struct sockaddr_in sin;
	int i;
	bool ret = false;

	ratelimit_init(&rl_test);

	sin.sin_family = AF_INET;
	sin.sin_port = 1234;

	/* Test that the garbage collect routine will run. */
	if (rl_test.rl_table_num != 0)
		T_FAILED("init not empty");

	for (i = 0; i < RATELIMIT_SIZE_MAX / 2; i++) {
		sin.sin_addr.s_addr = i;
		if (ratelimit_allow(&rl_test, sintosa(&sin)) != 0)
			T_FAILED_ITER("insert");
	}

	if (rl_test.rl_table_num != RATELIMIT_SIZE_MAX / 2)
		T_FAILED("insert 1 not full");

	tsleep(&rl_test, 0, "rl_test", ELEMENT_TIMEOUT * hz / 2);

	for (i = 0; i < RATELIMIT_SIZE_MAX / 2; i++) {
		sin.sin_addr.s_addr = i;
		if (ratelimit_allow(&rl_test, sintosa(&sin)) != 0)
			T_FAILED_ITER("insert");
	}

	if (rl_test.rl_table_num != RATELIMIT_SIZE_MAX / 2)
		T_FAILED("insert 2 not full");

	tsleep(&rl_test, 0, "rl_test", ELEMENT_TIMEOUT * hz * 2);

	if (rl_test.rl_table_num != 0)
		T_FAILED("gc");

	T_PASSED;
	ret = true;

cleanup:
	ratelimit_deinit(&rl_test);
	return (ret);
}

static bool
cookie_mac_test(void)
{
	struct cookie_checker *checker;
	struct cookie_maker *maker;
	struct cookie_macs cm;
	struct sockaddr_in sin;
	uint8_t nonce[COOKIE_NONCE_SIZE];
	uint8_t cookie[COOKIE_ENCRYPTED_SIZE];
	uint8_t shared[COOKIE_INPUT_SIZE];
	uint8_t message[T_MESSAGE_LEN];
	int res, i;
	bool ret = false;

	karc4random_buf(shared, COOKIE_INPUT_SIZE);
	karc4random_buf(message, T_MESSAGE_LEN);

	/* Init cookie_maker. */
	maker = cookie_maker_alloc(shared);

	checker = cookie_checker_alloc();
	cookie_checker_update(checker, shared);

	/* Create dummy sockaddr. */
	sin.sin_family = AF_INET;
	sin.sin_len = sizeof(sin);
	sin.sin_addr.s_addr = 1;
	sin.sin_port = 51820;

	/* MAC message. */
	cookie_maker_mac(maker, &cm, message, T_MESSAGE_LEN);

	/* Check we have a null mac2. */
	for (i = 0; i < sizeof(cm.mac2); i++) {
		if (cm.mac2[i] != 0)
			T_FAILED("validate_macs_noload_mac2_zeroed");
	}

	/* Validate all bytes are checked in mac1. */
	for (i = 0; i < sizeof(cm.mac1); i++) {
		cm.mac1[i] = ~cm.mac1[i];
		if (cookie_checker_validate_macs(checker, &cm, message,
						 T_MESSAGE_LEN, 0,
						 sintosa(&sin)) != EINVAL)
			T_FAILED("validate_macs_noload_munge");
		cm.mac1[i] = ~cm.mac1[i];
	}

	/* Check mac2 is zeroed. */
	res = 0;
	for (i = 0; i < sizeof(cm.mac2); i++)
		res |= cm.mac2[i];
	if (res != 0)
		T_FAILED("validate_macs_mac2_checkzero");


	/* Check we can successfully validate the MAC. */
	if (cookie_checker_validate_macs(checker, &cm, message, T_MESSAGE_LEN,
					 0, sintosa(&sin)) != 0)
		T_FAILED("validate_macs_noload_normal");

	/* Check we get a EAGAIN if no mac2 and under load. */
	if (cookie_checker_validate_macs(checker, &cm, message, T_MESSAGE_LEN,
					 1, sintosa(&sin)) != EAGAIN)
		T_FAILED("validate_macs_load_normal");

	/* Simulate a cookie message. */
	cookie_checker_create_payload(checker, &cm, nonce, cookie,
				      sintosa(&sin));

	/* Validate all bytes are checked in cookie. */
	for (i = 0; i < sizeof(cookie); i++) {
		cookie[i] = ~cookie[i];
		if (cookie_maker_consume_payload(maker, nonce, cookie)
		    != EINVAL)
			T_FAILED("consume_payload_munge");
		cookie[i] = ~cookie[i];
	}

	/* Check we can actually consume the payload. */
	if (cookie_maker_consume_payload(maker, nonce, cookie) != 0)
		T_FAILED("consume_payload_normal");

	/* Check replay isn't allowed. */
	if (cookie_maker_consume_payload(maker, nonce, cookie) != ETIMEDOUT)
		T_FAILED("consume_payload_normal_replay");

	/* MAC message again, with MAC2. */
	cookie_maker_mac(maker, &cm, message, T_MESSAGE_LEN);

	/* Check we added a mac2. */
	res = 0;
	for (i = 0; i < sizeof(cm.mac2); i++)
		res |= cm.mac2[i];
	if (res == 0)
		T_FAILED("validate_macs_make_mac2");

	/* Check we get OK if mac2 and under load */
	if (cookie_checker_validate_macs(checker, &cm, message, T_MESSAGE_LEN,
					 1, sintosa(&sin)) != 0)
		T_FAILED("validate_macs_load_normal_mac2");

	/* Check we get EAGAIN if we munge the source IP. */
	sin.sin_addr.s_addr = ~sin.sin_addr.s_addr;
	if (cookie_checker_validate_macs(checker, &cm, message, T_MESSAGE_LEN,
					 1, sintosa(&sin)) != EAGAIN)
		T_FAILED("validate_macs_load_spoofip_mac2");
	sin.sin_addr.s_addr = ~sin.sin_addr.s_addr;

	/* Check we get OK if mac2 and under load */
	if (cookie_checker_validate_macs(checker, &cm, message, T_MESSAGE_LEN,
					 1, sintosa(&sin)) != 0)
		T_FAILED("validate_macs_load_normal_mac2_retry");

	T_PASSED;
	ret = true;

cleanup:
	cookie_checker_free(checker);
	cookie_maker_free(maker);
	return (ret);
}

bool
cookie_selftest(void)
{
	bool ret = true;

	ret &= cookie_ratelimit_timings_test();
	ret &= cookie_ratelimit_capacity_test();
	ret &= cookie_ratelimit_gc_test();
	ret &= cookie_mac_test();

	kprintf("%s: %s\n", __func__, ret ? "pass" : "FAIL");
	return (ret);
}

#undef T_MESSAGE_LEN
#undef T_FAILED_ITER
#undef T_FAILED
#undef T_PASSED
