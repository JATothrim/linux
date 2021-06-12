// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2019 Google, Inc.
 *
 * Author:
 *	Sami Tolvanen <samitolvanen@google.com>
 *
 * This software is licensed under the terms of the GNU General Public
 * License version 2, as published by the Free Software Foundation, and
 * may be copied, distributed, and modified under those terms.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 */

#define pr_fmt(fmt) "pgo: " fmt

#include <asm/sections.h>
#include <linux/bitops.h>
#include <linux/kernel.h>
#include <linux/export.h>
#include <linux/spinlock.h>
#include <linux/types.h>
#include <linux/rculist.h>
#include "pgo.h"

/*
 * This lock guards both profile count updating and serialization of the
 * profiling data. Keeping both of these activities separate via locking
 * ensures that we don't try to serialize data that's only partially updated.
 */
static DEFINE_SPINLOCK(pgo_lock);

unsigned long prf_lock(void)
{
	unsigned long flags;

	spin_lock_irqsave(&pgo_lock, flags);

	return flags;
}

void prf_unlock(unsigned long flags)
{
	spin_unlock_irqrestore(&pgo_lock, flags);
}

/*
 * Return prf_object for the llvm_prf_data or NULL
 * if we should not attempt any profiling.
 */
static struct prf_object *find_prf_object(struct llvm_prf_data *p)
{
	struct prf_object *po = NULL;
	struct llvm_prf_data *data_end;

	rcu_read_lock();
	list_for_each_entry_rcu(po, &prf_list, link) {
		/*
		 * Check that p is within:
		 * [po->data, po->data + prf_data_count(po)] section.
		 */
		data_end = po->data + prf_data_count(po);
		if (memory_contains(po->data, data_end, p, sizeof(*p)))
			goto found;
	}
	/* not found */
	po = NULL;

found:
	rcu_read_unlock();
	return po;
}

/*
 * Counts the number of times a target value is seen.
 *
 * Records the target value for the index if not seen before. Otherwise,
 * increments the counter associated w/ the target value.
 */
void noinstr __llvm_profile_instrument_target(u64 target_value, void *data, u32 index)
{
	struct llvm_prf_data *p = (struct llvm_prf_data *)data;
	struct llvm_prf_value_node **counters;
	struct llvm_prf_value_node *curr;
	struct llvm_prf_value_node *min = NULL;
	struct llvm_prf_value_node *prev = NULL;
	struct prf_object *po;
	u64 min_count = U64_MAX;
	u8 values = 0;
	unsigned long flags;

	/* Get prf_object */
	po = find_prf_object(p);

	if (!po || !p || !p->values)
		return;

	counters = (struct llvm_prf_value_node **)p->values;
	curr = READ_ONCE(counters[index]);

	while (curr) {
		if (target_value == curr->value) {
			curr->count++;
			return;
		}

		if (curr->count < min_count) {
			min_count = curr->count;
			min = curr;
		}

		prev = curr;
		curr = READ_ONCE(curr->next);
		values++;
	}

	if (values >= LLVM_INSTR_PROF_MAX_NUM_VAL_PER_SITE) {
		if (!min->count || !(--min->count)) {
			curr = min;
			curr->value = target_value;
			curr->count++;
		}
		return;
	}

	/* Lock when updating the value node structure. */
	flags = prf_lock();

	if (WARN_ON_ONCE(po->current_node >= prf_vnds_count(po)))
		goto out; /* Out of nodes */

	/* reserve the vnode */
	curr = &po->vnds[po->current_node++];

	curr->value = target_value;
	curr->count++;

	if (!counters[index])
		WRITE_ONCE(counters[index], curr);
	else if (prev && !prev->next)
		WRITE_ONCE(prev->next, curr);

out:
	prf_unlock(flags);
}
EXPORT_SYMBOL(__llvm_profile_instrument_target);

/* Counts the number of times a range of targets values are seen. */
void __llvm_profile_instrument_range(u64 target_value, void *data, u32 index,
				     s64 precise_start, s64 precise_last,
				     s64 large_value)
{
	if (large_value != S64_MIN && (s64)target_value >= large_value)
		target_value = large_value;
	else if ((s64)target_value < precise_start ||
		 (s64)target_value > precise_last)
		target_value = precise_last + 1;

	__llvm_profile_instrument_target(target_value, data, index);
}
EXPORT_SYMBOL(__llvm_profile_instrument_range);

static u64 inst_prof_get_range_rep_value(u64 value)
{
	if (value <= 8)
		/* The first ranges are individually tracked, use it as is. */
		return value;
	else if (value >= 513)
		/* The last range is mapped to its lowest value. */
		return 513;
	else if (hweight64(value) == 1)
		/* If it's a power of two, use it as is. */
		return value;

	/* Otherwise, take to the previous power of two + 1. */
	return ((u64)1 << (64 - __builtin_clzll(value) - 1)) + 1;
}

/*
 * The target values are partitioned into multiple ranges. The range spec is
 * defined in compiler-rt/include/profile/InstrProfData.inc.
 */
void __llvm_profile_instrument_memop(u64 target_value, void *data,
				     u32 counter_index)
{
	u64 rep_value;

	/* Map the target value to the representative value of its range. */
	rep_value = inst_prof_get_range_rep_value(target_value);
	__llvm_profile_instrument_target(rep_value, data, counter_index);
}
EXPORT_SYMBOL(__llvm_profile_instrument_memop);
